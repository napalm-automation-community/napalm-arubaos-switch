Value Filldown Member (\d)
Value Required NUM (\S+)
Value STATE (\S+\s+\S+)
Value FAILURES (\d+)
Value LOCATION (\S+)

Start
  ^.*Fan Information -> Fans

Fans
  ^Member\s+${Member}
  ^${NUM}\s+\|\s+${STATE}\s+\|\s+${FAILURES}\s+\|\s+${LOCATION} -> Record
