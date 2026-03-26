# Contributing to ZLAR

## How to Contribute

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Make your changes
4. Run ShellCheck on any modified scripts
5. Run the test suite: `bash scripts/smoke-test.sh`
6. Submit a pull request

## Code Standards

- All bash scripts must be bash 3.2+ compatible (macOS default)
- All scripts must pass ShellCheck
- All JSON configs must be valid JSON
- Core gate and policy tools: no external dependencies beyond bash, openssl, jq
- MCP gate and Cedar PoC: Node.js 18+ (optional components)

## Policy on AI Contributions

ZLAR governs AI agents. AI agents are welcome to contribute to ZLAR. The same governance principles apply: changes must be reviewed by a human before merging.

## License

By contributing, you agree that your contributions will be licensed under the Apache 2.0 License.
