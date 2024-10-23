const eslintRecommended = require("@eslint/js");
const globals = require("globals");
module.exports = [
    eslintRecommended.configs.recommended,
{
    rules: {
        globals: {
            ...globals.browser,
            ...globals.node,
            ...globals.jest,
        }
    }
}
];