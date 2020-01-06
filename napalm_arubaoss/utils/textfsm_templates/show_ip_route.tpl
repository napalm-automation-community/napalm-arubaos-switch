Value Required DESTINATION (\S+)
Value GATEWAY (\S+)
Value VLAN ([0-9]*)
Value TYPE (\w+)
Value SUBTYPE (\S*)
Value METRIC ([0-9]+)
Value DISTANCE ([0-9]+)


Start
  ^.*IP Route Entries -> Routes

Routes
  ^\s+${DESTINATION}\s+${GATEWAY}\s+${VLAN}\s+${TYPE}\s+${SUBTYPE}\s+${METRIC}\s+${DISTANCE} -> Record

