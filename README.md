# ct

This simple tool will import certificate transparancy logs into Elasticsearch. The current version isn't verifying the authenticity of the Merkle tree.

## Import all certificates into local Elasticsearch
```sh
$ ./ct https://ct.googleapis.com/rocketeer/ 0 
```

