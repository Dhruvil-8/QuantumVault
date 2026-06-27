// @ts-check

/** @type {import('@docusaurus/plugin-content-docs').SidebarsConfig} */
const sidebars = {
  tutorialSidebar: [
    'index',
    'quickstart',
    {
      type: 'category',
      label: 'Concepts',
      items: [
        'concepts/hybrid-kem',
        'concepts/key-format',
        'concepts/threat-model',
      ],
    },
    {
      type: 'category',
      label: 'API References',
      items: [
        'rust-api',
        'python-api',
        'wasm-api',
        'c-api',
      ],
    },
  ],
};

module.exports = sidebars;
