# Development Workflow

This document defines the standard workflow and rules for development work within the XXXX project.

## 🚨 Most Important Rule: TODO List Management

### Absolute Requirement

**All work must be managed through the TODO list.**

#### 1. Phases of Work

We divide work into the following phases. You shouldn't perform multiple phases concurrently, except for small tasks (under 50 lines of code) or when explicitly instructed to do so. If step2 and step3 nad it is not in example code, refer docs/coding-standards folder to check style. 

1. Information Gathering and Design Document Creation
2. Unit Testing in source code style. Compile successfully, but test fails.
3. Source Code Modification, Compilation, Unit Testing, and Operational Verification by Running the Application
4. Proposal of Refactoring Candidates
5. Execution of Refactoring

#### 2. Areas of Work

When implementing new features, we'll ask you to create a design document for each one.

#### 3. Mandatory Steps Before Starting Work

1. Always check docs/TODO.md.
2. For new work requests:
   - Immediately add to TODO.md.
   - Set priority.
   - Organize relationships with existing tasks.
3. For existing tasks:
   - Confirm the status of the relevant task.
   - Record the start of work in TODO.md.

#### 4. Tasks After Modifying Instructed Source Code

If you receive instructions to modify features or refactor code, and these instructions differ from the existing implementation policy regarding coding style or libraries used, please propose the changes as a commented-out section in the files under `docs/coding-standards`. Include the date and information about which task it was related to.
