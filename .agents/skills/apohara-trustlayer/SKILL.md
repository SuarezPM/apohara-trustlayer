```markdown
# apohara-trustlayer Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches the core development patterns and conventions used in the `apohara-trustlayer` TypeScript codebase. It covers file organization, code style, commit message standards, and testing approaches to help maintain consistency and quality across contributions.

## Coding Conventions

### File Naming
- Use **camelCase** for file names.
  - Example: `userProfile.ts`, `trustLayerConfig.ts`

### Imports
- Use **relative imports** for internal modules.
  - Example:
    ```typescript
    import { getUser } from './userService';
    ```

### Exports
- Use **named exports** for all modules.
  - Example:
    ```typescript
    export function validateTrustLayer() { ... }
    export const TRUST_LAYER_VERSION = '1.0.0';
    ```

### Commit Messages
- Follow **Conventional Commits** with the `chore` prefix.
  - Example:
    ```
    chore: update dependencies to latest versions
    ```

## Workflows

### Dependency Update
**Trigger:** When dependencies need to be updated.
**Command:** `/update-deps`

1. Check for outdated dependencies.
2. Update dependencies in `package.json`.
3. Run tests to ensure compatibility.
4. Commit changes using a conventional commit message:
    ```
    chore: update dependencies to latest versions
    ```
5. Push changes and open a pull request.

### Code Refactoring
**Trigger:** When improving code structure without changing functionality.
**Command:** `/refactor`

1. Identify code that can be improved (e.g., simplify logic, rename variables).
2. Refactor code following coding conventions.
3. Run all tests to ensure no regressions.
4. Commit changes with a message like:
    ```
    chore: refactor userProfile logic for clarity
    ```
5. Push changes and create a pull request.

## Testing Patterns

- Test files follow the `*.test.*` pattern.
  - Example: `userService.test.ts`
- The specific testing framework is not detected; refer to existing test files for structure.
- Place tests alongside the modules they test or in a dedicated `tests` directory if present.
- Example test file:
    ```typescript
    import { getUser } from './userService';

    describe('getUser', () => {
      it('should return user data for valid ID', () => {
        // test implementation
      });
    });
    ```

## Commands
| Command        | Purpose                                      |
|----------------|----------------------------------------------|
| /update-deps   | Update all project dependencies              |
| /refactor      | Refactor code for clarity or maintainability |
```
