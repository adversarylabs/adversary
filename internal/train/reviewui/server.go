// Package reviewui serves the private catalog candidate inbox on localhost.
package reviewui

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/adversarylabs/adversary/internal/train/results"
)

const tokenHeader = "X-Adversary-Review-Token"

type Options struct {
	StateRoot   string
	Adversaries []string
	Output      io.Writer
	Entropy     io.Reader
	Listen      func(string, string) (net.Listener, error)
	OpenURL     func(context.Context, string) error
}

// Serve starts a loopback-only review server and blocks until it is closed or
// the command context is canceled.
func Serve(ctx context.Context, opts Options) error {
	secret := make([]byte, 32)
	if _, err := io.ReadFull(opts.Entropy, secret); err != nil {
		return fmt.Errorf("create review token: %w", err)
	}
	token := base64.RawURLEncoding.EncodeToString(secret)
	listener, err := opts.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return fmt.Errorf("start catalog review server: %w", err)
	}
	defer listener.Close()

	server := &http.Server{ReadHeaderTimeout: 5 * time.Second}
	server.Handler = NewHandler(opts.StateRoot, opts.Adversaries, token, func() {
		go server.Shutdown(context.Background())
	})
	pageURL := "http://" + listener.Addr().String() + "/?token=" + url.QueryEscape(token)
	if opts.Output != nil {
		fmt.Fprintf(opts.Output, "Catalog training review: %s\n", pageURL)
		fmt.Fprintln(opts.Output, "The review UI is local to this machine. Press Ctrl-C or use Close review UI when finished.")
	}
	if err := opts.OpenURL(ctx, pageURL); err != nil && opts.Output != nil {
		fmt.Fprintf(opts.Output, "Could not open a browser automatically: %v\n", err)
	}
	go func() {
		<-ctx.Done()
		_ = server.Shutdown(context.Background())
	}()
	err = server.Serve(listener)
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

// NewHandler constructs the authenticated HTTP UI. It is exported for focused
// transport tests; production callers should use Serve.
func NewHandler(stateRoot string, adversaries []string, token string, shutdown func()) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		if !validToken(r.URL.Query().Get("token"), token) {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = io.WriteString(w, page(token, adversaries))
	})
	mux.HandleFunc("GET /api/candidates", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, token) {
			return
		}
		rows, err := results.List(stateRoot, "", "")
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, rows)
	})
	mux.HandleFunc("POST /api/candidates/{id}/{action}", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, token) {
			return
		}
		id, action := strings.TrimSpace(r.PathValue("id")), r.PathValue("action")
		var err error
		switch action {
		case "accept":
			err = results.Accept(stateRoot, id)
		case "dismiss":
			err = results.Dismiss(stateRoot, id)
		case "reopen":
			err = results.Reopen(stateRoot, id)
		default:
			http.Error(w, "unknown action", http.StatusNotFound)
			return
		}
		if err != nil {
			writeError(w, err)
			return
		}
		row, err := results.Get(stateRoot, id)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, row)
	})
	mux.HandleFunc("PATCH /api/candidates/{id}", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, token) {
			return
		}
		defer r.Body.Close()
		var edit struct {
			Adversary    string `json:"adversary"`
			ProposedRule string `json:"proposed_rule"`
		}
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&edit); err != nil {
			http.Error(w, "invalid edit", http.StatusBadRequest)
			return
		}
		id := strings.TrimSpace(r.PathValue("id"))
		if strings.TrimSpace(edit.Adversary) == "" || strings.TrimSpace(edit.ProposedRule) == "" {
			http.Error(w, "adversary and proposed rule are required", http.StatusBadRequest)
			return
		}
		if err := results.ReassignCatalogCandidate(stateRoot, id, edit.Adversary); err != nil {
			writeError(w, err)
			return
		}
		if err := results.UpdateCatalogProposedRule(stateRoot, id, edit.ProposedRule); err != nil {
			writeError(w, err)
			return
		}
		row, err := results.Get(stateRoot, id)
		if err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, row)
	})
	mux.HandleFunc("POST /api/shutdown", func(w http.ResponseWriter, r *http.Request) {
		if !authorize(w, r, token) {
			return
		}
		w.WriteHeader(http.StatusNoContent)
		if shutdown != nil {
			shutdown()
		}
	})
	return securityHeaders(mux)
}

func validToken(got, expected string) bool {
	return len(got) == len(expected) && subtle.ConstantTimeCompare([]byte(got), []byte(expected)) == 1
}

func authorize(w http.ResponseWriter, r *http.Request, token string) bool {
	if !validToken(r.Header.Get(tokenHeader), token) {
		http.Error(w, "not found", http.StatusNotFound)
		return false
	}
	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeError(w http.ResponseWriter, err error) {
	http.Error(w, err.Error(), http.StatusBadRequest)
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func page(token string, adversaries []string) string {
	tokenJSON, _ := json.Marshal(token)
	adversariesJSON, _ := json.Marshal(adversaries)
	return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Adversary catalog training</title><style>
:root{color-scheme:light dark;--bg:#f7f5f1;--panel:#fffdfa;--ink:#25211d;--muted:#6f675f;--line:#d9d2c9;--accent:#c4512c;--good:#217a50;--bad:#b93838;--diff-add:#e1f4e7;--diff-del:#fbe5e2;--diff-num:#f2eee8;--comment-head:#faf3ec}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}button,input,select,textarea{font:inherit}header{height:68px;padding:0 24px;border-bottom:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;background:var(--panel);box-shadow:0 1px 0 rgba(50,35,20,.03)}header strong{font-size:16px}.brand{display:inline-flex;align-items:center;gap:8px}.brand:before{content:"A";width:26px;height:26px;border-radius:8px;display:grid;place-items:center;background:var(--accent);color:#fff;font-weight:800}.subhead{color:var(--muted);margin-left:12px}.layout{display:grid;grid-template-columns:360px minmax(0,1fr);height:calc(100vh - 68px)}aside{border-right:1px solid var(--line);overflow:auto;background:var(--panel)}.tools{position:sticky;top:0;padding:16px;background:var(--panel);border-bottom:1px solid var(--line);z-index:1}.tools input{width:100%;padding:9px;border:1px solid var(--line);border-radius:8px;background:var(--bg)}.filters{display:flex;gap:6px;margin-top:10px}.filters button,.quiet{border:1px solid var(--line);background:transparent;border-radius:999px;padding:5px 9px;cursor:pointer}.filters .active{background:var(--accent);border-color:var(--accent);color:#fff}#list{padding:8px}.card{padding:12px;border-radius:8px;cursor:pointer;border:1px solid transparent}.card:hover,.card.active{background:var(--bg);border-color:var(--line)}.card.active{box-shadow:inset 3px 0 var(--accent)}.card-top{display:flex;justify-content:space-between;gap:8px}.owner{font-weight:650}.status{font-size:11px;text-transform:uppercase;color:var(--muted)}.summary{margin-top:5px;color:var(--muted);display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden}main{overflow:auto;padding:32px max(28px,5vw)}.empty{color:var(--muted);margin-top:20vh;text-align:center}.eyebrow{color:var(--accent);font-weight:700;text-transform:uppercase;font-size:11px;letter-spacing:.08em}h1{font-size:25px;line-height:1.25;margin:8px 0 5px}.meta{color:var(--muted);display:flex;gap:14px;flex-wrap:wrap}.review-file{border:1px solid var(--line);border-radius:10px;margin:26px 0 30px;overflow:hidden;background:var(--panel);box-shadow:0 8px 24px rgba(65,45,25,.05)}.file-head{padding:10px 14px;background:var(--comment-head);border-bottom:1px solid var(--line);font:600 13px ui-monospace,SFMono-Regular,Consolas,monospace;display:flex;justify-content:space-between}.diff{overflow-x:auto;font:12px/20px ui-monospace,SFMono-Regular,Consolas,monospace}.diff-line{display:grid;grid-template-columns:48px 48px minmax(max-content,1fr);min-height:20px;white-space:pre}.diff-line .num{color:var(--muted);background:var(--diff-num);border-right:1px solid var(--line);text-align:right;padding:0 8px;user-select:none}.diff-line code{padding:0 10px;font:inherit}.diff-line.add,.diff-line.add .num{background:var(--diff-add)}.diff-line.del,.diff-line.del .num{background:var(--diff-del)}.diff-line.hunk{display:block;padding:3px 10px;color:var(--accent);background:color-mix(in srgb,var(--accent) 9%,var(--panel))}.no-hunk{padding:22px;color:var(--muted);font-family:ui-monospace,SFMono-Regular,Consolas,monospace}.review-comment{margin:14px;border:1px solid color-mix(in srgb,var(--accent) 48%,var(--line));border-radius:8px;overflow:hidden}.comment-head{display:flex;align-items:center;gap:8px;padding:9px 12px;background:color-mix(in srgb,var(--accent) 8%,var(--panel));border-bottom:1px solid color-mix(in srgb,var(--accent) 28%,var(--line))}.avatar{width:24px;height:24px;border-radius:8px;display:grid;place-items:center;background:var(--accent);color:#fff;font-weight:700;font-size:11px}.comment-head strong{font-weight:650}.comment-head a{margin-left:auto;color:var(--accent);text-decoration:none}.comment-body{font-size:15px;line-height:1.55;padding:14px 16px;white-space:pre-wrap}label{display:block;font-weight:650;margin:18px 0 7px}main input,select,textarea{width:100%;border:1px solid var(--line);border-radius:8px;padding:10px;background:var(--panel);color:var(--ink)}textarea{min-height:130px;resize:vertical}.rationale{margin:22px 0;color:var(--muted)}.actions{display:flex;gap:9px;margin-top:24px;flex-wrap:wrap}button.action{border:1px solid transparent;border-radius:8px;padding:8px 14px;cursor:pointer;font-weight:650}.save{background:var(--ink);color:var(--panel)}.accept{background:var(--good);color:#fff}.dismiss{background:var(--bad);color:#fff}.reopen{background:#a56a13;color:#fff}.link{color:var(--accent)}#message{min-height:22px;margin-top:12px;color:var(--muted)}@media(prefers-color-scheme:dark){:root{--bg:#12100e;--panel:#1c1916;--ink:#f3eee8;--muted:#aaa098;--line:#3e3832;--accent:#f07b51;--good:#278a59;--bad:#d94c4c;--diff-add:#14281e;--diff-del:#30191a;--diff-num:#211d19;--comment-head:#261d18}}@media(max-width:760px){.layout{grid-template-columns:1fr;height:auto}aside{height:42vh;border-right:0;border-bottom:1px solid var(--line)}main{padding:24px}}
</style></head><body><header><div><strong class="brand">Adversary training workspace</strong><span class="subhead" id="count"></span></div><button class="quiet" id="close">Close workspace</button></header><div class="layout"><aside><div class="tools"><input id="search" placeholder="Search review evidence"><div class="filters" id="filters"></div></div><div id="list"></div></aside><main id="detail"><div class="empty">Select training evidence to review.</div></main></div>
<script>
const TOKEN=` + string(tokenJSON) + `, ADVERSARIES=` + string(adversariesJSON) + `;let rows=[],selected=null,filter='new';
const esc=s=>String(s??'');const api=async(path,opts={})=>{opts.headers={...(opts.headers||{}),'X-Adversary-Review-Token':TOKEN};const r=await fetch(path,opts);if(!r.ok)throw new Error(await r.text());return r.status===204?null:r.json()};
function filtered(){const q=document.querySelector('#search').value.toLowerCase();return rows.filter(r=>(filter==='all'||r.status===filter)&&[r.summary,r.pr_title,r.package,r.comment_author,r.pr_author].join(' ').toLowerCase().includes(q))}
function renderList(){const visible=filtered();document.querySelector('#count').textContent=` + "`" + `${rows.filter(r=>r.status==='new').length} to review · ${rows.length} total` + "`" + `;document.querySelector('#list').replaceChildren(...visible.map(r=>{const x=document.createElement('div');x.className='card'+(r.id===selected?' active':'');const top=document.createElement('div');top.className='card-top';const owner=document.createElement('span');owner.className='owner';owner.textContent=r.package||'unassigned';const status=document.createElement('span');status.className='status';status.textContent=r.status;top.append(owner,status);const summary=document.createElement('div');summary.className='summary';summary.textContent=r.summary;x.append(top,summary);x.onclick=()=>{selected=r.id;renderList();renderDetail()};return x}));if(selected&&!rows.some(r=>r.id===selected))selected=null}
function renderFilters(){const box=document.querySelector('#filters');box.replaceChildren(...['new','accepted','dismissed','all'].map(name=>{const b=document.createElement('button');b.textContent=name;b.className=name===filter?'active':'';b.onclick=()=>{filter=name;renderFilters();renderList()};return b}))}
function diffPanel(r){const panel=document.createElement('div');panel.className='review-file';const head=document.createElement('div');head.className='file-head';const path=document.createElement('span');path.textContent=r.file||'General PR comment';const location=document.createElement('span');location.textContent=r.line?'line '+r.line:'';head.append(path,location);panel.append(head);const diff=document.createElement('div');diff.className='diff';if(r.diff_hunk){let oldLine=0,newLine=0;for(const raw of r.diff_hunk.split('\n')){const row=document.createElement('div');if(raw.startsWith('@@')){row.className='diff-line hunk';row.textContent=raw;const m=raw.match(/@@ -(\d+)(?:,\d+)? \+(\d+)/);if(m){oldLine=Number(m[1]);newLine=Number(m[2])}diff.append(row);continue}const add=raw.startsWith('+'),del=raw.startsWith('-');row.className='diff-line '+(add?'add':del?'del':'context');const old=document.createElement('span'),next=document.createElement('span'),code=document.createElement('code');old.className=next.className='num';if(!add)old.textContent=oldLine++;if(!del)next.textContent=newLine++;code.textContent=raw;row.append(old,next,code);diff.append(row)}}else{const missing=document.createElement('div');missing.className='no-hunk';missing.textContent=r.file?(r.line?'Context at line '+r.line:'Inline diff context unavailable'):'This was a general PR review comment.';diff.append(missing)}panel.append(diff);const comment=document.createElement('div');comment.className='review-comment';const commentHead=document.createElement('div');commentHead.className='comment-head';const avatar=document.createElement('span');avatar.className='avatar';const who=(r.comment_author||'?').replace(/^@/,'');avatar.textContent=who.slice(0,2).toUpperCase();const author=document.createElement('strong');author.textContent=who==='?'?'Unknown reviewer':'@'+who;const said=document.createElement('span');said.textContent='commented';commentHead.append(avatar,author,said);if(r.comment_url){const link=document.createElement('a');link.href=r.comment_url;link.target='_blank';link.rel='noreferrer';link.textContent='View on GitHub';commentHead.append(link)}const body=document.createElement('div');body.className='comment-body';body.textContent=r.summary;comment.append(commentHead,body);panel.append(comment);return panel}
function renderDetail(){const main=document.querySelector('#detail'),r=rows.find(x=>x.id===selected);if(!r){main.innerHTML='<div class="empty">Select a training candidate to review.</div>';return}main.replaceChildren();const eyebrow=document.createElement('div');eyebrow.className='eyebrow';eyebrow.textContent=r.status+' · '+r.id;const h=document.createElement('h1');h.textContent=r.pr_title||'Human review concern';const meta=document.createElement('div');meta.className='meta';const prAuthor=r.pr_author?'PR opened by @'+r.pr_author.replace(/^@/,''):'PR author unavailable';const reviewer=r.comment_author?'reviewed by @'+r.comment_author.replace(/^@/,''):'reviewer unavailable';for(const value of [prAuthor,reviewer]){const s=document.createElement('span');s.textContent=value;meta.append(s)}const ownerLabel=document.createElement('label');ownerLabel.textContent='Route to adversary (choose one or type a new id)';const owner=document.createElement('input');owner.id='owner';owner.setAttribute('list','adversary-list');owner.value=r.package||'unassigned';const choices=document.createElement('datalist');choices.id='adversary-list';for(const id of ['unassigned',...ADVERSARIES.filter(x=>x!=='unassigned')]){const o=document.createElement('option');o.value=id;choices.append(o)}const ruleLabel=document.createElement('label');ruleLabel.textContent='Proposed private rule';const rule=document.createElement('textarea');rule.id='rule';rule.value=r.proposed_rule||'';const rationale=document.createElement('div');rationale.className='rationale';rationale.textContent=r.triage_reason?'Model rationale: '+r.triage_reason:'No model rationale recorded.';const actions=document.createElement('div');actions.className='actions';actions.append(button('Save edits','action save',save));if(r.status==='new'){actions.append(button('Accept','action accept',()=>decide('accept')),button('Dismiss','action dismiss',()=>decide('dismiss')))}else actions.append(button('Reopen','action reopen',()=>decide('reopen')));if(r.pr_url){const a=document.createElement('a');a.href=r.pr_url;a.target='_blank';a.rel='noreferrer';a.className='action link';a.textContent='Open PR';actions.append(a)}const message=document.createElement('div');message.id='message';main.append(eyebrow,h,meta,diffPanel(r),ownerLabel,owner,choices,ruleLabel,rule,rationale,actions,message)}
function button(label,cls,fn){const b=document.createElement('button');b.textContent=label;b.className=cls;b.onclick=fn;return b}async function save(){try{const updated=await api('/api/candidates/'+encodeURIComponent(selected),{method:'PATCH',headers:{'Content-Type':'application/json'},body:JSON.stringify({adversary:document.querySelector('#owner').value,proposed_rule:document.querySelector('#rule').value})});replace(updated);note('Saved')}catch(e){note(e.message,true)}}async function decide(action){try{const updated=await api('/api/candidates/'+encodeURIComponent(selected)+'/'+action,{method:'POST'});rows=rows.map(x=>x.id===updated.id?updated:x);filter='new';if(action!=='reopen')selected=(rows.find(x=>x.status==='new')||updated).id;renderFilters();renderList();renderDetail()}catch(e){note(e.message,true)}}function replace(r){rows=rows.map(x=>x.id===r.id?r:x);renderList();renderDetail()}function note(s,bad=false){const x=document.querySelector('#message');if(x){x.textContent=s;x.style.color=bad?'var(--bad)':'var(--good)'}}
document.querySelector('#search').oninput=renderList;document.querySelector('#close').onclick=async()=>{await api('/api/shutdown',{method:'POST'});document.body.innerHTML='<main><div class="empty">Review UI closed. You can close this tab.</div></main>'};(async()=>{rows=await api('/api/candidates');renderFilters();renderList();const first=rows.find(r=>r.status==='new')||rows[0];if(first){selected=first.id;renderList();renderDetail()}})().catch(e=>{document.querySelector('#detail').textContent=e.message});
</script></body></html>`
}
