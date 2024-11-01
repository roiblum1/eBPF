from pydantic import BaseModel, computed_field
from typing import Optional

class GlobalMap(BaseModel):
    total_packet_count: int
    total_packet_length: int
    total_ttl: int
    @computed_field
    @property
    def volume(self) -> float:
        if(self.total_packet_count > 0):
            return self.total_packet_length / self.total_packet_count
        else:
            return 0
        