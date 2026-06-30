# Adversary

Adversary runs containerized source-code adversaries against a local repository.

## Usage

```sh
adversary run adversarylabs/dockerfile
adversary run adversarylabs/github-actions --repo .
adversary run adversarylabs/github-actions --base main --head HEAD
adversary run adversarylabs/github-actions --force
```

An adversary reference can be either a local directory containing `adversary.yaml` or a direct container image reference.

## Example Local Adversary

Build the sample Dockerfile adversary:

```sh
docker build -t adversarylabs/dockerfile-adversary:0.1.0 examples/dockerfile-adversary
```

Run it against the current repository:

```sh
adversary run examples/dockerfile-adversary --repo .
```
