// @ts-check

/** @type {import('@docusaurus/types').Config} */
const config = {
  title: 'QuantumVault PQC SDK',
  tagline: 'The opinionated libsodium of post-quantum cryptography.',
  favicon: 'img/favicon.ico',
  url: 'https://Dhruvil-8.github.io',
  baseUrl: '/QuantumVault/',
  organizationName: 'Dhruvil-8',
  projectName: 'QuantumVault',
  onBrokenLinks: 'warn',
  onBrokenMarkdownLinks: 'warn',
  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },
  presets: [
    [
      'classic',
      /** @type {import('@docusaurus/preset-classic').Options} */
      ({
        docs: {
          sidebarPath: './sidebars.js',
          routeBasePath: '/', // Serve the docs at the site's root
        },
        blog: false,
        theme: {
          customCss: './src/css/custom.css',
        },
      }),
    ],
  ],
  themeConfig:
    /** @type {import('@docusaurus/preset-classic').ThemeConfig} */
    ({
      navbar: {
        title: 'QuantumVault',
        items: [
          {
            type: 'docSidebar',
            sidebarId: 'tutorialSidebar',
            position: 'left',
            label: 'Documentation',
          },
          {
            href: 'https://github.com/Dhruvil-8/QuantumVault',
            label: 'GitHub',
            position: 'right',
          },
        ],
      },
      footer: {
        style: 'dark',
        links: [
          {
            title: 'Docs',
            items: [
              {
                label: 'Quickstart',
                to: '/quickstart',
              },
              {
                label: 'Concepts',
                to: '/concepts/hybrid-kem',
              },
            ],
          },
        ],
        copyright: `Copyright © ${new Date().getFullYear()} QuantumVault. AI-generated codebase disclaimer applies.`,
      },
    }),
};

module.exports = config;
