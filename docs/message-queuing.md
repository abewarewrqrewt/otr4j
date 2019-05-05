# Message queueing

The considerations for the _message queueing_ functionality as it needs to work in _otr4j_.

# General behavior

1. User sends a message. Action taken is determined by the current session state:
  - `PLAINTEXT`:
    - _Secure messaging required_: queue message for later transmission.
    - _Otherwise_: send message in plain text.
  - `WAITING AUTH-R` / `AUTH-I`: queue message for later transmission.
  - `ENCRYPTED_MESSAGES` (_OTRv3_/_OTRv4_): create Data Message and transmit.
  - `FINISHED`: queue message for later transmission.

1. Queue is sent upon transitioning to encrypted session.

# Open issues

1. If messages are queued and multiple instances are being established simultaneously, should we send queued messages to first established instance session?
  - Risk that messages go to other instance session than user is currently using, due to multiple clients being on-line.  
    On-line client does not imply user is present at that location.
  - If we need to select one out of many instances, do we wait or pick the first instance that establishes an encrypted session? (Which in no way guarantees that it is the user's client.)
2. If one instance session is in non-`PLAINTEXT` state, e.g. state `WAITING AUTH-R`, and another is in state `PLAINTEXT` (may be _master session_), then how do we determine from the master session whether we should _send message as plaintext_ or _queue message for later secure transmission_?
