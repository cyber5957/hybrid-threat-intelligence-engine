#This file defines what an evidence object looks like 
from pydantic import BaseModel , Field
from datetime import datetime

class Evidence(BaseModel):
    ioc :str = Field(strict=True)
    ioc_type : str
    source : str
    finding : str
    verdict : str
    confidence : str
    timestamp : datetime
    reference : str

evidence_data = Evidence(ioc=5698, ioc_type="type of ioc", source="sourceoftheip",
                         finding="what are the findings of the ip", verdict="ip final verdict",
                         confidence="finalipconfidence", timestamp=datetime.now(),
                         reference="referenceoftheip")

print(evidence_data)

