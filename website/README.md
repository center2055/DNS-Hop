# DNS Hop Website

Interactive marketing site for DNS Hop, hosted from the main `DNS-Hop` repository under `/website`.

## Stack

- Vite
- React 19
- TypeScript
- Framer Motion

## Local development

```powershell
npm install
npm run dev
```

## Production build

```powershell
npm run build
```

## Deployment

The main repository includes the GitHub Pages workflow at `.github/workflows/website.yml`.
It resolves the correct project-site base path automatically during the build.
