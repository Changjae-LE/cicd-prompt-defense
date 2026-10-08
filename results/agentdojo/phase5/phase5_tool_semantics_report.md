# AgentDojo Phase 5 Tool semantics analysis

## Native behavior

- `search_calendar_events`: AgentDojo native Tool raises `ValueError` when its search returns no events.
- `search_emails`: AgentDojo native Tool raises `ValueError` when its search returns no emails.
- `search_contacts_by_name` / `search_contacts_by_email`: native Inbox methods raise `ValueError` when no contact matches.
- `update_scheduled_transaction`: native Tool raises `ValueError` when the requested transaction ID is absent.
- `get_users_in_channel`: native Tool raises `ValueError` when the channel is absent.

These exceptions originate inside AgentDojo 0.1.35 suite code after schema validation. They are benchmark Tool outcomes, not adapter transport or schema failures.

## Model feedback

AgentDojo `FunctionsRuntime.run_function` preserves errors as `ErrorType: message`. Its OpenAI adapter sends `message['error']` verbatim as the next Tool message content. Phase 5 therefore records a parallel structured outcome but does not replace the raw feedback; replacing it would change the frozen model trajectory and benchmark semantics.

## Observed non-defense error events in the existing Phase 4 actual run

- `search_calendar_events`: 9
- `get_users_in_channel`: 4
- `search_contacts_by_email`: 3
- `update_scheduled_transaction`: 2
- `search_contacts_by_name`: 1
- `search_emails`: 1

No fallback entities, fake results, default channels, or synthetic transactions were introduced.
