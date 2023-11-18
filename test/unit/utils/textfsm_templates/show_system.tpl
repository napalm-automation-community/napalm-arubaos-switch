Value Filldown Member (\d)
Value Required CPU (\d+)
Value MemTotal (.{5,})
Value MemFree (.{5,})

Start
  ^.*General System -> System

System
  ^\s+Member\s+:${Member}
  ^.*Total\s+:\s${MemTotal}
  ^.*CPU\sUtil\s\(%\)\s+:\s${CPU} -> Continue
  ^.*Free\s+:\s${MemFree} -> Record