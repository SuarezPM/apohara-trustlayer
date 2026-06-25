```markdown
# apohara-trustlayer Development Patterns

> Auto-generated skill from repository analysis

## Overview
This skill teaches you the development patterns and conventions used in the `apohara-trustlayer` Rust codebase. You'll learn how to structure files, write imports and exports, follow commit message conventions, and implement and run tests in line with the repository's standards.

## Coding Conventions

### File Naming
- Use **snake_case** for all file names.
  - Example: `trust_layer.rs`, `user_manager.rs`

### Import Style
- Use **relative imports** within the crate.
  - Example:
    ```rust
    mod user_manager;
    use crate::user_manager::User;
    ```

### Export Style
- Use **named exports** for modules and functions.
  - Example:
    ```rust
    pub struct TrustLayer { /* ... */ }
    pub fn verify_trust() { /* ... */ }
    ```

### Commit Messages
- Follow **Conventional Commits** with the `feat` prefix for new features.
  - Example:
    ```
    feat: add trust verification logic for user onboarding
    ```

## Workflows

### Adding a New Feature
**Trigger:** When implementing a new feature in the codebase  
**Command:** `/add-feature`

1. Create a new file using snake_case, e.g., `new_feature.rs`.
2. Implement your feature using relative imports and named exports.
3. Write or update tests in a corresponding `*.test.*` file.
4. Commit your changes using the `feat:` prefix and a descriptive message.
   - Example: `feat: implement user trust score calculation`
5. Push your branch and open a pull request.

### Writing and Running Tests
**Trigger:** When you need to verify functionality  
**Command:** `/run-tests`

1. Create or update test files matching the `*.test.*` pattern.
2. Write tests according to Rust's standard testing conventions.
   - Example:
     ```rust
     #[cfg(test)]
     mod tests {
         use super::*;

         #[test]
         fn test_trust_score() {
             assert_eq!(calculate_trust(42), 100);
         }
     }
     ```
3. Run tests using Cargo:
   ```
   cargo test
   ```

## Testing Patterns

- Test files follow the `*.test.*` naming pattern.
- Tests are written using Rust's built-in test framework (annotate test functions with `#[test]`).
- Place tests in a `mod tests` section within the module or in separate test files.

  Example:
  ```rust
  #[cfg(test)]
  mod tests {
      use super::*;

      #[test]
      fn test_example() {
          assert_eq!(2 + 2, 4);
      }
  }
  ```

## Commands
| Command        | Purpose                                         |
|----------------|-------------------------------------------------|
| /add-feature   | Start the workflow for adding a new feature     |
| /run-tests     | Run the complete test suite                     |
```
