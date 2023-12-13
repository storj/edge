# Writing a Basic Test Plan Guide

## Why Write Test Plans?

We believe test plans are crucial for effective software development. Drafting them early serves as a checklist. After implementation, they help identify bugs by comparing against the plan. Early reviews also empower developers to prevent most issues. Hence, the sooner we create a test plan, the better we can prevent bugs!

## Writing a Basic Test Plan

### Test Name

Let's consider tests for the multinode dashboard UI:

1. Add new node with correct information
2. Add new node with incorrect information
3. Add new node with existing node information

#### Test Scenarios

Grouping these tests under the scenario "New Node Button Functionality":

- Add new node with correct information
- Add new node with incorrect information
- Add new node with existing node information

#### Test Description

Describing the expected outcomes using conditional statements:

1. If a user adds a new node with correct information, they should see node details.
2. If a user adds a new node with incorrect information, an error message should appear.
3. If a user adds an existing node, they should receive an error message.

*For instance, if Test 2 fails, the user won't see node details and won't receive an error message.*

#### Comments

This section allows users to add comments, highlighting why tests were added, improvements needed, and actual outcomes when deviating from expectations. For instance, if an error message is missing despite incorrect information in Test 2, users can comment on the anomaly.

## Test Plan Template and Submission

Once you've completed the plan, use the following template:

```
|  Test Scenario  	|   Test Case   	|  Test Description 	|    Comments   	|
|:---------------:	|:-------------:	|:-----------------:	|:-------------:	|
| Test Scenario 1 	| Test Case 1.1 	| TC1.1 Description 	| TC1.1 Comment 	|
|                 	| Test Case 1.2 	| TC1.2 Description 	| TC1.2 Comment 	|
| Test Scenario 2 	| Test Case 2.1 	| TC2.1 Description 	| TC2.1 Comment 	|
|                 	| Test Case 2.2 	| TC2.2 Description 	| TC2.2 Comment 	|
```
