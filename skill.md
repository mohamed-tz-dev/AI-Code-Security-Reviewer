\# AI Code Security Reviewer — System Instruction File (SKILL.md)



\## Project Identity



AI Code Security Reviewer is a repository-level security analysis platform that scans full software projects and identifies security vulnerabilities before deployment.



\## Core Objective



Analyze an uploaded project (ZIP or Git repository) and produce a structured security report covering source code risks, insecure patterns, and architectural weaknesses.



\## Primary Scope (MVP)



The system must:



\* Accept full project upload or Git repository URL

\* Extract all source files

\* Detect supported programming languages

\* Analyze each source file for security issues

\* Aggregate findings into a single project-level report

\* Store scan history in PostgreSQL



\## Security Checks Required



The analysis engine must inspect for:



\* SQL Injection

\* Cross-site scripting (XSS)

\* Command injection

\* Hardcoded secrets

\* Authentication flaws

\* Authorization issues

\* Unsafe file handling

\* Unsafe deserialization

\* Path traversal

\* Input validation issues

\* Insecure API usage

\* Dependency-related security risks (future phase)



\## System Architecture



\### Frontend



\* React or Next.js dashboard

\* Repository upload UI

\* Scan results page

\* History page



\### Backend



\* Node.js + Express API

\* JWT authentication

\* File upload handler

\* Git clone service

\* Scan job orchestration



\### Worker Layer



\* BullMQ workers

\* Redis queue

\* Async scan processing



\### Analysis Engine



1\. Repository ingestion

2\. File parser

3\. Static analysis

4\. AI analysis

5\. Aggregation

6\. Report generation



\### Database



PostgreSQL tables:



\* users

\* scans

\* vulnerabilities

\* scan\_reports

\* audit\_logs



\## Repository Analysis Logic



\### Step 1: Ingest Project



\* Accept ZIP or repo URL

\* Extract into temporary workspace



\### Step 2: Traverse Files



Supported file types:



\* .js

\* .ts

\* .py

\* .java

\* .php

\* .go

\* .cpp

\* .cs



Ignore:



\* node\_modules

\* dist

\* build

\* .git

\* binaries



\### Step 3: Chunking



For each file:



\* split by function/class/module

\* preserve file path metadata

\* attach language



\### Step 4: Static Rules



Run deterministic rules first:



\* regex rules

\* AST rules

\* secret detection



\### Step 5: AI Security Review



Send chunk to AI with prompt:



\* analyze only security issues

\* classify severity

\* explain evidence

\* propose fix



\### Step 6: Merge Results



\* remove duplicates

\* group by file

\* calculate project score



\## Output Format



The final report must include:



1\. Summary

2\. Vulnerabilities found

3\. Severity distribution

4\. Security score

5\. Suggested fixes



\## Non-Goals for MVP



Do not build yet:



\* CI/CD integration

\* Pull request comments

\* Auto-fix commits

\* Vector database

\* Full dependency graph

\* IDE plugin



\## Phase 2 Expansion



After MVP add:



\* Cross-file data flow analysis

\* GitHub App integration

\* RAG security knowledge base

\* Team dashboard

\* PDF export

\* AI remediation assistant



\## Development Rules



\* Never execute uploaded code directly

\* Always sandbox uploaded files

\* Limit file size

\* Rate limit API requests

\* Store API keys in environment variables only

\* Use parameterized SQL queries only



\## Suggested Folder Structure



```text

/backend

&#x20; /src

&#x20;   /api

&#x20;   /services

&#x20;   /workers

&#x20;   /analyzers

&#x20;   /db

/frontend

&#x20; /src

/postgres

/docs

```



\## Success Criteria



MVP is successful when:



\* A developer uploads a full project

\* The system scans all files

\* Security issues are detected accurately

\* Report is saved and displayed



