# Contributing to VSOS

Thank you for your interest in contributing to VSOS. This is a novel AI security architecture — contributions span from low-level system engineering to security rule design to visualization.

## How to Contribute

1. **Fork** the repository
2. **Create a branch** for your work (`git checkout -b feature/your-feature`)
3. **Make your changes** with clear commit messages
4. **Submit a Pull Request** with a description of what and why

## Code Standards

- Python code follows PEP 8
- All detection logic must be explainable (no pure black-box models in the adjudication pipeline)
- Attack DNA must be persistently traceable (every decision needs a causal chain)
- Do not introduce hard-coded keyword lists without justification — VSOS uses variable-essence analysis, not keyword matching

## Security Principles

When contributing, please respect VSOS's core invariant:

- **Every attack must leave a trace** — no silent bypass
- **Poison anchors are permanent** — do not add logic that can remove confirmed dangerous coordinates
- **Soil only grows** — danger zone expands monotonically, never contracts
- **All decisions are auditable** — each verdict must have a causal chain

## Detection Rule Guidelines

- New anchors should cover one clear attack dimension
- Include test cases (SAFE/BLOCK/WARNING) when submitting new detection logic
- Run `python vsos_guard.py` to verify the 134-sample test suite still passes (target: 98%+ accuracy)

## Discussion

For architecture discussions and design questions, open an Issue with the `discussion` label.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
