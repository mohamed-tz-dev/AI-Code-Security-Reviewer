system-design.md

Component Design

1\. API Service



Responsibilities:



Receive uploads

Validate requests

Create scan jobs

Return results

2\. Scanner Service



Responsibilities:



Extract repository

Traverse files

Filter unsupported files

3\. Analysis Service



Responsibilities:



Static scanning

AI analysis

Result normalization

4\. Persistence Layer



Responsibilities:



Save scans

Save vulnerabilities

Save audit logs

5\. Frontend Dashboard



Pages:



Login

Upload project

Scan history

Report details

Request Flow



User Upload → API → Queue → Worker → Analyzer → DB → UI



Future Extensions

GitHub integration

Pull request scanning

CI/CD hooks

Team collaboration

PDF export

