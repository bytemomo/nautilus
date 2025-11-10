# MQTT \$SYS TOPIC DISCLOSURE

This module will check that subscribing to \# do not get also \$SYS related topics
as this can enable an attacker (that have access to a client) to learn informations
about the system (e.g. connections, topics etc..).

## General Info

This module will:

1. open a connection to the broker as a subscriber and will subscribe
   to # topic.
2. open a connection to the broker as a publisher and publish to a random topic
   to trigger the update of $SYS topics.
3. See if the subscriber gets the $SYS topic update.

In the case in which the $SYS topic update is reached it flags the findings as true.
