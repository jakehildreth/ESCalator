# Issue tracker: GitHub

Issues and specs live as GitHub issues. Use the `gh` CLI.
Infer the repository from the current clone's Git remote.

## Conventions

Use a Markdown file with `--body-file` for multi-line bodies.

- Create: `gh issue create --title "..." --body-file <path>`.
- Read, including comments and labels: `gh issue view <number> --json number,title,body,labels,comments,assignees,state,url`.
- List: `gh issue list --state open --json number,title,body,labels,assignees,url`. Adjust label and state filters as needed.
- Comment: `gh issue comment <number> --body-file <path>`.
- Apply labels: `gh issue edit <number> --add-label "..."`.
- Remove labels: `gh issue edit <number> --remove-label "..."`.
- Close: `gh issue close <number>`.

"Publish to the issue tracker" means create a GitHub issue.
"Fetch the relevant ticket" means read the issue, including its comments.

## Pull requests as a triage surface

**PRs as a request surface: no.**

## Wayfinding operations

Used by `/wayfinder`.

- Map: one issue labelled `wayfinder:map`. Its body contains Destination, Notes, Decisions so far, Not yet specified, and Out of scope.
- Child ticket: a GitHub sub-issue of the map, linked through `gh api`. Apply one type label: `wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`, or `wayfinder:task`.
- If sub-issues are unavailable, track children in a task list on the map. Add `Part of: [map title](map URL)` to each child.
- Blocking: use native issue dependencies. Add an edge with `gh api --method POST repos/<owner>/<repo>/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`.
- Look up the blocker's numeric database ID with `gh api repos/<owner>/<repo>/issues/<number> --jq .id`. Do not use its issue number or node ID.
- If native dependencies are unavailable, add `Blocked by: [ticket title](ticket URL)` at the top of the child body. A ticket is unblocked when all blockers are closed.
- Frontier: query the map's open children, using its sub-issues or fallback task list. Exclude assigned tickets and tickets with any open blocker. Take the first remaining ticket in map order.
- Claim: `gh issue edit <number> --add-assignee "@me"`. Assign before working on the ticket.
- Resolve: post the answer as a comment, close the ticket, then append a linked ticket title and one-line gist to the map's Decisions so far. Keep the detailed answer only on the ticket.

Create child issues before wiring their blocking edges.
Use linked titles when referring to maps and tickets.
