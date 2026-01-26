const helmRegex = {
  customType: "regex",
  datasourceTemplate: "helm",
  matchStringsStrategy: "combination",
};

module.exports = {
  username: "renovate[bot]",
  gitAuthor: "Renovate Bot <bot@renovateapp.com>",
  onboarding: false,
  platform: "github",
  forkProcessing: "disabled",
  dryRun: null,
  packageRules: [
    {
      matchDatasources: ["helm", "docker", "github-releases"],
    },
    {
      matchDatasources: ["go"],
      matchFileNames: ["go.mod"],
      description: "Go dependencies in root"
    },
  ],
};
