from dataclasses import dataclass

@dataclass(frozen=True)

class IOC:
    ioc_type: str
    ioc_value: str