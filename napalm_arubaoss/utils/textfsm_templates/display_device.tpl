Value INTERFACE_ID ([\w\.-/]+)
Value STATE (\w+)
Value DESCRIPTION ([\w\s]+)
Value SPEED (\d+)
Value MAC ([a-fA-F0-9-]+)

Start
  ^\s${INTERFACE_ID}\scurrent state: ${STATE}
  ^\sDescription: ${DESCRIPTION}
  ^.*Hardware Address: ${MAC}
  ^\s${SPEED}\w+-speed mode -> Record