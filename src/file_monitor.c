#include "file_monitor.h"

// Hash function for file paths
static unsigned int hash_path(const char *path) {
	unsigned int hash = 5381;
	int c;
	while ((c = *path++))
		hash = ((hash << 5) + hash) + c;
	return hash % MAX_FILE_CACHE;
}

// Calculate MD5 hash of file content
static bool calculate_file_hash(const char *filepath, unsigned char *hash) {
    FILE *file = fopen(filepath, "rb");
    if (!file) return false;
    
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        fclose(file);
        return false;
    }
    
    if (EVP_DigestInit_ex(ctx, EVP_md5(), NULL) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return false;
    }
    
    unsigned char buffer[8192];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        if (EVP_DigestUpdate(ctx, buffer, bytes) != 1) {
            EVP_MD_CTX_free(ctx);
            fclose(file);
            return false;
        }
    }
    
    unsigned int hash_len;
    if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
        EVP_MD_CTX_free(ctx);
        fclose(file);
        return false;
    }
    
    EVP_MD_CTX_free(ctx);
    fclose(file);
    return true;
}

// Get or create file state entry
struct file_state *get_file_state(const char *path) {
	unsigned int idx = hash_path(path);
	struct file_state *entry = file_cache[idx];
	
	// Search for existing entry
	while (entry) {
		if (strcmp(entry->path, path) == 0) {
			return entry;
		}
		entry = entry->next;
	}
	
	// Create new entry if not found and cache isn't full
	if (cache_entries < MAX_FILE_CACHE) {
		entry = malloc(sizeof(struct file_state));
		if (entry) {
			strncpy(entry->path, path, PATH_MAX - 1);
			entry->path[PATH_MAX - 1] = '\0';
			memset(entry->hash, 0, HASH_SIZE);
			entry->last_modified = 0;
      entry->file_exists = false;
			entry->next = file_cache[idx];
			file_cache[idx] = entry;
			cache_entries++;
		}
	}
	
	return entry;
}

bool is_new_file_creation(const char *filepath) {
    struct file_state *state = get_file_state(filepath);
    if (!state) {
        return true;
    }
    
    if (state->file_exists) {
        return false;  // Already exists in our tracking
    }
    
    state->file_exists = true;  // Mark as existing
    return true;  // This is new
}

// Check if file content has actually changed
bool has_content_changed(const char *filepath) {
	if (!env.content_aware) {
		return true;  // If content checking disabled, assume changed
	}
	
	struct file_state *state = get_file_state(filepath);
	if (!state) {
		return true;  // If can't track, assume changed
	}
	
	unsigned char new_hash[HASH_SIZE];
	if (!calculate_file_hash(filepath, new_hash)) {
		return true;  // If can't read file, assume changed
	}
	
	// Compare with stored hash
	bool changed = (memcmp(state->hash, new_hash, HASH_SIZE) != 0);
	
	// Update stored hash if changed or if this is first time
	if (changed || state->last_modified == 0) {
		memcpy(state->hash, new_hash, HASH_SIZE);
		state->last_modified = time(NULL);
	}
	
	return changed;
}

// Clean up file cache
void cleanup_file_cache() {
	for (int i = 0; i < MAX_FILE_CACHE; i++) {
		struct file_state *entry = file_cache[i];
		while (entry) {
			struct file_state *next = entry->next;
			free(entry);
			entry = next;
		}
		file_cache[i] = NULL;
	}
	cache_entries = 0;
}
