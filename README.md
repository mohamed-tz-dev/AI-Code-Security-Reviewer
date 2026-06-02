README.md

Overview



AI Code Security Reviewer is a web-based system that scans full software projects and detects security vulnerabilities using static analysis and AI-assisted reasoning.



Tech Stack

Frontend: React / Next.js

Backend: Node.js + Express

Database: PostgreSQL

Queue: Redis + BullMQ

AI Engine: OpenAI or local LLM

MVP Modules

Authentication

Repository Upload

Repository Scanner

AI Analysis Engine

Report Viewer

Scan History

Local Development

Clone repository

Install backend dependencies

Configure PostgreSQL

Configure environment variables

Install Python 3 and make sure it is available on PATH for Python AST analysis of `.py` files.

Install Semgrep and make it available on PATH to enable repository-wide Semgrep scanning. Example:

pip install semgrep

Start backend server

Start frontend server

Environment Variables

DATABASE\_URL

JWT\_SECRET

OPENAI\_API\_KEY

REDIS\_URL

