# odd-jobs

A vault for small, purpose-built scripts and mini-projects.

## Disclaimer

Most scripts here are one-off solutions built to solve a single specific task.
They are kept for archive/reference, and many are not meant to be reused.
Do not expect the cleanest code or polished structure in every project.

## Layout

```text
.
├── scripts/
│   └── <project_slug>/
├── reports/
│   └── <project_slug>/
└── README.md
```

## Conventions

- Keep each job isolated under one `project_slug`.
- Store executable code in `scripts/<project_slug>/`.
- Store usage/context docs in `reports/<project_slug>/`.
- Use consistent names so scripts and reports are easy to match.
