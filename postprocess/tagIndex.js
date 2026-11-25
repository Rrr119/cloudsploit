/**
 * Builds a resource tag index from a CloudSploit collection cache.
 *
 * The index maps every known resource identifier (ARN, resource id and,
 * where applicable, name) to a normalized { tagName: tagValue } object so
 * that suppression rules can be evaluated without any knowledge of the
 * underlying cloud provider API shapes.
 *
 * The module is intentionally generic: it understands the AWS tag
 * representations ({Key,Value} arrays, TagSet arrays and key/value maps)
 * and falls back to indexing any object carrying a Tags property.
 */

/**
 * Normalizes the various tag representations returned by cloud APIs into
 * a plain { name: value } object. Returns null when no tags are present.
 */
function normalizeTags(rawTags) {
    if (!rawTags) return null;

    var normalized = {};
    var found = false;

    if (Array.isArray(rawTags)) {
        rawTags.forEach(function(tag) {
            if (!tag) return;
            if (tag.Key !== undefined && tag.Value !== undefined) {
                normalized[tag.Key] = tag.Value;
                found = true;
            } else if (tag.Key !== undefined && tag.tagValue !== undefined) {
                normalized[tag.Key] = tag.tagValue;
                found = true;
            }
        });
    } else if (typeof rawTags === 'object') {
        // S3 getBucketTagging style: { TagSet: [...] }
        if (Array.isArray(rawTags.TagSet)) {
            return normalizeTags(rawTags.TagSet);
        }
        Object.keys(rawTags).forEach(function(key) {
            if (typeof rawTags[key] === 'string') {
                normalized[key] = rawTags[key];
                found = true;
            }
        });
    }

    return found ? normalized : null;
}

/**
 * Registers a resource under all identifiers it exposes.
 */
function register(indexed, identifiers, tags) {
    if (!tags) return;
    identifiers.filter(function(id) { return id; }).forEach(function(id) {
        indexed[id] = tags;
    });
}

/**
 * Iterates over every region entry of a cached API call. Each region entry
 * is either { data: [...] } (collection style) or a map keyed by an
 * extra resource identifier (per-resource calls such as S3 getBucket*).
 */
function eachRegionEntry(cacheNode, callback) {
    if (!cacheNode) return;
    Object.keys(cacheNode).forEach(function(region) {
        var entry = cacheNode[region];
        if (!entry) return;
        if (Array.isArray(entry.data)) {
            entry.data.forEach(function(item) {
                callback(item, region, null);
            });
        } else if (typeof entry === 'object') {
            Object.keys(entry).forEach(function(extra) {
                var perResource = entry[extra];
                if (perResource && perResource.data) {
                    if (perResource.data.TagSet) {
                        callback(perResource.data, region, extra);
                    } else if (Array.isArray(perResource.data)) {
                        perResource.data.forEach(function(item) {
                            callback(item, region, extra);
                        });
                    } else {
                        callback(perResource.data, region, extra);
                    }
                } else if (perResource && perResource.TagSet) {
                    callback(perResource, region, extra);
                }
            });
        }
    });
}

/**
 * Indexes EC2-style describe* collections (security groups, volumes,
 * instances, ENIs, etc.). Resources are keyed by ARN when present and by
 * their resource id (GroupId, VolumeId, InstanceId, ...) as a fallback.
 */
function indexEc2Collection(indexed, cache, callName, idField) {
    var node = cache.ec2 && cache.ec2[callName];
    eachRegionEntry(node, function(item) {
        var tags = normalizeTags(item.Tags);
        if (!tags) return;
        var identifiers = [];
        if (item.Arn) identifiers.push(item.Arn);
        if (idField && item[idField]) {
            identifiers.push(item[idField]);
        }
        register(indexed, identifiers, tags);
    });
}

/**
 * Indexes S3 bucket tags. Buckets are keyed by bucket name and bucket ARN.
 */
function indexS3Buckets(indexed, cache) {
    var taggingNode = cache.s3 && cache.s3.getBucketTagging;
    eachRegionEntry(taggingNode, function(data, region, bucketName) {
        if (!bucketName) return;
        var tags = normalizeTags(data);
        register(indexed, [
            bucketName,
            'arn:aws:s3:::' + bucketName,
            'arn:aws-cn:s3:::' + bucketName,
            'arn:aws-us-gov:s3:::' + bucketName
        ], tags);
    });
}

/**
 * Generic fallback: walks the entire cache and indexes every object that
 * carries a Tags/TagSet property, using any id-like field available. This
 * keeps the index useful for resources without dedicated handling and for
 * plugins beyond the three covered explicitly.
 */
function genericIndexWalk(indexed, value) {
    if (!value || typeof value !== 'object') return;

    if (Array.isArray(value)) {
        value.forEach(function(item) { genericIndexWalk(indexed, item); });
        return;
    }

    var tags = normalizeTags(value.Tags || value.TagSet);
    if (tags) {
        var identifiers = [value.Arn, value.ResourceId, value.Id,
            value.GroupId, value.VolumeId, value.InstanceId,
            value.BucketName, value.Name];
        register(indexed, identifiers, tags);
    }

    Object.keys(value).forEach(function(key) {
        if (key === 'Tags' || key === 'TagSet') return;
        genericIndexWalk(indexed, value[key]);
    });
}

/**
 * Builds the tag index for a collection cache.
 *
 * @param {Object} cache The collected API metadata passed to plugins.
 * @return {Object} Map of resource identifier -> { tagName: tagValue }.
 */
function build(cache) {
    var indexed = {};
    if (!cache || typeof cache !== 'object') return indexed;

    if (cache.ec2) {
        indexEc2Collection(indexed, cache, 'describeSecurityGroups', 'GroupId');
        indexEc2Collection(indexed, cache, 'describeVolumes', 'VolumeId');
        indexEc2Collection(indexed, cache, 'describeInstances', 'InstanceId');
        indexEc2Collection(indexed, cache, 'describeNetworkInterfaces', 'NetworkInterfaceId');
    }

    if (cache.s3) {
        indexS3Buckets(indexed, cache);
    }

    genericIndexWalk(indexed, cache);

    return indexed;
}

/**
 * Looks up the tags for a result resource, tolerating ARN partition and
 * account-id differences by also matching the resource id suffix.
 */
function lookup(indexed, resource) {
    if (!resource) return null;
    if (indexed[resource]) return indexed[resource];

    // ARN suffix match: arn:partition:service:region:account:resource-id
    var suffix = resource.split('/').pop();
    if (suffix && suffix !== resource && indexed[suffix]) return indexed[suffix];

    return null;
}

module.exports = {
    build: build,
    lookup: lookup,
    normalizeTags: normalizeTags
};
