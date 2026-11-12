// Launch arguments for child windows are passed as FERMION_ARG=<base64> and
// decoded by the preload (src/preload.js readLaunchArgs).
const EXTRA_ARG_PREFIX="FERMION_ARG="

function wrapExtraArgs(args) {
    return args.map((x) => EXTRA_ARG_PREFIX + btoa(x))
}

module.exports = {
    wrapExtraArgs: wrapExtraArgs,
}
