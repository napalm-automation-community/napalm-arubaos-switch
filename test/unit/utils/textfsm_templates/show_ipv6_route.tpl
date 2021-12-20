Value DESTINATION ([0-9a-z:/%]+)
Value GATEWAY (\w+)
Value VLAN (\w+)
Value TYPE ([SCOR])
Value SUBTYPE ([A-Z0-9][A-Z0-9])
Value METRIC ([0-9]+)
Value DISTANCE ([0-9]+)


Start
  ^.*IPv6 Route Entries -> Routes

Routes
  ^\s${DESTINATION}\s+
  ^\s+${GATEWAY}\s(\(${VLAN}\))?\s+${TYPE}\s+${SUBTYPE}\s+${DISTANCE}\s+${METRIC} -> Record
