Value INTERFACE_ID ([\w\.-/]+)
Value IS_UP (\w+)
Value DESCRIPTION ([\w\s]+)
Value SPEED (\d+|\w+)
Value MAC_ADDRESS ([a-fA-F0-9-]+)

Start
  ^\s${INTERFACE_ID}\scurrent state: ${IS_UP}
  ^\sDescription: ${DESCRIPTION}
  ^.*Hardware Address: ${MAC_ADDRESS}
  ^\s${SPEED}.*-speed mode -> Record