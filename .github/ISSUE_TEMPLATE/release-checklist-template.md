---
name: "\u270D Release Checklist Template"
about: "Template for Release Checklist"
title: "Release Checklist"
labels: "edge"
---

# Revision vX.Y.Z

## Release Requirements

- [ ] Prepare config changes if needed (see _Open Issues/Regressions/Comments_)
- [ ] Follow steps in [MAINTAINERS.md](https://github.com/storj/edge/blob/main/MAINTAINERS.md)
- [ ] Run _UI-based tests_
- [ ] Run _Folder sharing tests_

## UI-based tests

- [ ] verify upload works (text file, image file, video file)
- [ ] verify download works (text file, image file, video file)
- [ ] verify file preview (text file, image file, video file)
- [ ] generate a linksharing link and verify the download works via an alternate browser session

## Folder sharing tests

- [ ] create "subfolder" (`demo/111/222`) and share access to it (give access to `…/222`)
- [ ] check there's no access to root "folders" and data in them

## Open Issues/Regressions/Comments

> In this section, regressions or any new issues that may effect customers can be brought up from the test results. This will be beneficial to the community members as well as anyone working support. This section may also contain any pertenant notes from the release coordinator.
