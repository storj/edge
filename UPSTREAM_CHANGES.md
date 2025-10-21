# Upstream Changes Required

This PR includes changes to the `storj.io/common` package that need to be upstreamed.

## Changes to storj.io/common/accesslogs

The following changes have been made to add configurable timeouts for parcel uploads:

### Files Modified

1. **accesslogs/processor.go**
   - Added `UploadTimeout` field to `Options.UploadingOptions` struct
   - Added default timeout of 5 minutes in `NewProcessor`
   - Passes `uploadTimeout` to `newSequentialUploader`

2. **accesslogs/uploader.go**
   - Added `uploadTimeout` field to `sequentialUploader` struct
   - Added `uploadTimeout` field to `sequentialUploaderOptions` struct
   - Updated `newSequentialUploader` to initialize `uploadTimeout`
   - Modified `run()` method to use `context.WithTimeout` instead of `context.TODO()`
   - Properly creates and cancels context for each upload operation

3. **accesslogs/uploader_test.go**
   - Updated all existing tests to include `uploadTimeout` parameter
   - Added new test `TestUploadTimeout` to verify timeout functionality

### Summary

This change addresses issue https://github.com/storj/edge/issues/XXX by:

1. Adding a configurable `UploadTimeout` option for parcel uploads
2. Replacing the `context.TODO()` with a proper timeout context
3. Setting a default timeout of 5 minutes
4. Making the timeout configurable through the Options struct
5. Ensuring all tests pass with the new timeout parameter

### Configuration

Users can configure the upload timeout through the command-line flag or configuration:

```
--access-logs-processor.uploading-options.upload-timeout=5m
```

The default value is 5 minutes if not specified.

### Testing

All existing tests pass, and a new test `TestUploadTimeout` has been added to verify that:
- Timeouts are properly enforced
- Context cancellation works correctly
- Upload operations respect the configured timeout

## Next Steps

1. These changes are currently applied using a `replace` directive in `go.mod`
2. They need to be submitted as a PR to the `storj/common` repository
3. Once merged in common, the replace directive should be removed
4. The edge repository should be updated to use the new version of common
