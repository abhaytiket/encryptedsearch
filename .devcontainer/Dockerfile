ARG GOLANG_VERSION=latest
FROM golang:${GOLANG_VERSION}
# gopls - go language server (https://pkg.go.dev/golang.org/x/tools/gopls)
RUN go install -v golang.org/x/tools/gopls@latest
# dlv -  debugger for golang (https://github.com/go-delve/delve)
RUN go install -v github.com/go-delve/delve/cmd/dlv@latest
# staticcheck - linter for golang (https://staticcheck.io/)
RUN go install -v honnef.co/go/tools/cmd/staticcheck@latest
# digraph - used for analysing dependency graph
RUN go install golang.org/x/tools/cmd/digraph@latest
# modgraphviz - used for visualizing dependency graph 
RUN go install golang.org/x/exp/cmd/modgraphviz@latest
# govulncheck - used for checking vulnerabilities in go modules
RUN go install golang.org/x/vuln/cmd/govulncheck@latest
