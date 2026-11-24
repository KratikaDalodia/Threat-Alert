# Threat Alert API

A small in-memory Go server. The security SDK reports threats, and company users view and resolve them.

## How to run
```
go run .
```
Listens on port 8080, or on `PORT` if set. Run tests with:
```
go test -race ./...
```
Docker: `docker build -t threatalert . && docker run -p 8080:8080 threatalert`

## Project structure
- `main.go`: starts the HTTP server, reads `PORT`, shuts down cleanly on Ctrl+C.
- `handlers.go`: routes, auth checks (401, then 403), input checks (400), JSON helpers.
- `store.go`: all in-memory data, one mutex, repeat-alert logic, company separation.
- `server_test.go`: tests (viewer 403, other company 404, 50 concurrent alerts, resolve then repeat).
- `Dockerfile`: multi-stage build for Cloud Run.
- `go.mod`: Go 1.22, no dependencies.

## What works and what does not
Works: all 7 routes, the 22-step self-check from the paper, `go test -race` passes, graceful shutdown, Dockerfile.
Not done: JSON persistence, `GET /summary`, `limit`/`offset` paging. Data is lost on restart. Emails are not checked for duplicates.

## How AI helped
- Tools I used: TODO
- Two prompts I used (paste them as you typed them): TODO
- One thing the AI got wrong, and how I found and fixed it: TODO
- One part I wrote or changed myself without AI: TODO

## Questions
1. Two identical alerts at the same moment: `ReportAlert` in `store.go` takes `s.mu.Lock()` (line 154) before it looks up the open alert (line 160) and holds it until the function returns. So "check if an open alert exists" and "create or update it" happen as one step. The second request waits, then finds the alert the first one created and just adds 1 to `count`. The new alert is stored in `openAlerts` (line 183) while the lock is still held.
2. If we answered 403, the user would learn that an alert with that id exists in another company. With 404, "someone else's alert" and "no such alert" look the same. `GetAlert` and `Resolve` in `store.go` (lines 213 and 224) only look at alerts whose `orgID` matches the caller's, and otherwise return "not found".
