Value Filldown Member (\d)
Value Required Sensor (\S+)
Value Temperature (\d+)
Value OverTemp (YES|NO)

Start
  ^.*Air -> Temperature

Temperature
  ^  Member  ${Member}
  ^  ${Sensor}\s+${Temperature}\S\s+\d+\S\s+\d+\S\s+\d+\S\s+${OverTemp} -> Record