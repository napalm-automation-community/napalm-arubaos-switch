Value INTERFACE_ID ([\w\.-/]+)
Value IS_ENABLED (\w+)

Start
  ^[ ]{2}Port
  ^[ ]{2}${INTERFACE_ID}.*[|]\s+\w+\s+${IS_ENABLED} -> Record