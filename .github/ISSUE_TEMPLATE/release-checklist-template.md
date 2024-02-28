---
name: "\u270D Release Checklist Template"
about: "Template for Release Checklist"
title: "Release Checklist"
labels: "edge"
assignees: "neo-cypher"
---

# Revision v1.XX.XX

```[tasklist]
#### Release Requirements
- [ ] Prepare Config Changes if Needed
- [ ] Follow the steps in [MAINTAINERS.md.](https://github.com/storj/edge/blob/main/MAINTAINERS.md)
- [ ] Run UI-based tests
- [ ] Run Folder sharing tests
- [ ] Run GetBucketLocation tests
```

```[tasklist]
#### UI-based tests
- [ ] verify upload functionality (text file, image file, video file)
- [ ] verify download functionality (text file, image file, video file)
- [ ] verify file preview (text file, image file, video file)
- [ ] generate linksharing link and verify download functionality via alternate browser session
```

```[tasklist]
#### Folder sharing tests
- [ ] create "subfolder" (`demo/111/222`) and share access to it (give access to `…/222`)
- [ ] check there's no access to root "folders" and data in them
```

```[tasklist]
#### GetBucketLocation tests
- [ ] Create a bucket
- [ ] Call GetBucketLocation (`aws --endpoint-url … s3api get-bucket-location --bucket …`)
- [ ] Ensure that the created bucket has the necessary location constraint as per [the documentation](https://docs.storj.io/dcs/api/s3/s3-compatibility#get-bucket-location)
```

## Open Issues/Regressions/Comments
> In this section, regressions or any new issues that may effect customers can be brought up from the test results. This will be beneficial to the community members as well as anyone working support. This section may also contain any pertenant notes from the release coordinator.
