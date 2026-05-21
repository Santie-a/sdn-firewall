# TODO / Future work

Enhancements identified during development, not yet implemented.

## Show the received message in the UI Event Log

**Status:** possible, not started.

The client can already echo the received `--message` payload to its **console**
log (`show_message` in `client/config.json`). It would also be possible to
surface that message in the controller's **Event Log** tab, so it is visible
and persisted in the UI rather than only on the node's terminal.

This is feasible but a larger change than the console version, because it
touches the server model, the client's event payload, and the UI:

- `server/models.py` — add a `message` (or `payload`) field to `PacketInfo`.
- `client/client.py` — include the decoded payload in the `packet` dict sent to
  `POST /events` via `_report_event()`.
- `interface/index.html` — add a "Message" column to the Event Log table header.
- `interface/app.js` — render the new field in `renderEvents()`.

Caveats for whoever picks this up:
- The payload is attacker-controlled text — render it through `esc()`; never inject it raw into the DOM.
- Truncate long payloads before storing/displaying.
- Decide whether to capture the message on every event or only when the client opts in (mirroring the `show_message` flag).
