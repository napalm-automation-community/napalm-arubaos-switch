Value Member (\d)
Value PS (\d)
Value State (\S+)
Value Wattage (\d+)
Value Max (\d+)

Start
  ^.*Member\s+PS#\s+Model\s+Serial\s+State\s+AC\/DC\s+\+\sV\s+Wattage\s+Max -> Member
  ^.*PS#\s+Model\s+Serial\s+State\s+AC\/DC\s+\+\sV\s+Wattage\s+Max -> Standalone

Standalone
  ^ ${PS}\s+\S+\s+\S+\s+${State}\s+\S\S\s\d+\S+\d+\S\s+${Wattage}\s+${Max} -> Record

Member
  ^  ${Member}\s+${PS}\s+\S+\s+\S+\s+${State}\s+\S\S\s\d+\S+\d+\S\s+${Wattage}\s+${Max} -> Record
