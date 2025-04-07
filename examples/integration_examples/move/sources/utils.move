module walrus::utils;

/// 检查一个字节向量是否是另一个字节向量的前缀
/// Returns true if `prefix` is a prefix of `word`.
/// 
/// @param prefix - 要检查的前缀字节向量
/// @param word - 被检查的完整字节向量
/// @return 如果prefix是word的前缀则返回true，否则返回false
public(package) fun is_prefix(prefix: vector<u8>, word: vector<u8>): bool {
    // 如果前缀长度大于完整字符串，则不可能是前缀
    if (prefix.length() > word.length()) {
        return false
    };
    let mut i = 0;
    // 逐字节比较前缀和目标字符串
    while (i < prefix.length()) {
        if (prefix[i] != word[i]) {
            return false
        };
        i = i + 1;
    };
    true
}
