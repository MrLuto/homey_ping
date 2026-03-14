Homey Ping

Monitor netwerkapparaten en gebruik hun online/offline status in Homey Flows.

Belangrijkste functies:
- Handmatig een host of IP toevoegen
- Periodieke bereikbaarheidstest via interval
- Probe-modus: Auto (ICMP -> TCP), ICMP only, TCP only
- Status-capability met duidelijke waarde: Online/Offline
- Handmatige controle via capability: Ping nu
- Flow kaarten:
  - Wanneer: Apparaat kwam online / ging offline
  - En: Is online / Is offline
  - Dan: Ping nu

Opmerking:
In sommige Homey omgevingen is geen ICMP ping-binary beschikbaar.
Gebruik in dat geval Auto of TCP only.
