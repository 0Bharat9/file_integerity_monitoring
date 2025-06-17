#!/bin/bash

# FIM Detection Test Script
# This script tests various file operations to validate FIM monitoring

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test directory
TEST_DIR="/tmp/fim_test_$(date +%s)"
BACKUP_DIR="/tmp/fim_backup_$(date +%s)"

echo -e "${BLUE}========================================${NC}"
echo -e "${BLUE}FIM Detection Test Script${NC}"
echo -e "${BLUE}========================================${NC}"
echo "Test directory: $TEST_DIR"
echo "Backup directory: $BACKUP_DIR"
echo ""

# Create test directories
mkdir -p "$TEST_DIR"
mkdir -p "$BACKUP_DIR"

log_test() {
  echo -e "${YELLOW}[TEST]${NC} $1"
  sleep 1 # Give FIM time to process
}

cleanup() {
  echo -e "\n${BLUE}Cleaning up test files...${NC}"
  rm -rf "$TEST_DIR" "$BACKUP_DIR" 2>/dev/null || true
}

trap cleanup EXIT

cd "$TEST_DIR"

echo -e "${GREEN}Starting FIM tests...${NC}\n"

# ===== FILE CREATION TESTS =====
log_test "1. Testing file creation with different methods"

# Direct file creation
echo "test content" >regular_file.txt
echo "#!/bin/bash\necho 'hello'" >script.sh

# Touch command
touch empty_file.txt touched_file.log

# Using different creation flags
echo "data" >created_with_redirect.dat
cat >created_with_cat.txt <<'EOF'
This file was created with cat
Multiple lines of content
EOF

# Create with specific permissions
echo "restricted" >restricted_file.txt
chmod 600 restricted_file.txt

log_test "2. Testing temporary file creation patterns"

# mktemp style
TEMP_FILE=$(mktemp "${TEST_DIR}/temp_XXXXXX")
echo "temporary data" >"$TEMP_FILE"

# Editor-style temporary files
echo "content" >.temp_file
echo "backup" >file.txt~
echo "swap" >.file.swp

# Hidden files
echo "hidden content" >.hidden_file
echo "config data" >.config

# ===== FILE MODIFICATION TESTS =====
log_test "3. Testing file modifications"

# Append operations
echo "appended line 1" >>regular_file.txt
echo "appended line 2" >>regular_file.txt

# Overwrite operations
echo "completely new content" >regular_file.txt
echo "overwritten" >empty_file.txt

# In-place editing simulation (like sed -i)
cp regular_file.txt regular_file.txt.bak
echo "edited content" >regular_file.txt
rm regular_file.txt.bak

# Binary file operations
dd if=/dev/zero of=binary_file.bin bs=1024 count=1 2>/dev/null
dd if=/dev/urandom of=random_file.bin bs=512 count=2 2>/dev/null

# ===== PERMISSION CHANGE TESTS =====
log_test "4. Testing chmod operations"

# Various chmod patterns
chmod 755 script.sh
chmod 644 regular_file.txt
chmod 600 restricted_file.txt
chmod 777 binary_file.bin

# Symbolic chmod
chmod u+x empty_file.txt
chmod g-w touched_file.log
chmod o-r random_file.bin

# Recursive chmod
mkdir -p subdir/nested
echo "nested file" >subdir/nested/file.txt
chmod -R 755 subdir/

# ===== OWNERSHIP CHANGE TESTS =====
log_test "5. Testing chown operations"

# Note: These may fail if not run as root, but will still trigger FIM events
chown $USER:$USER regular_file.txt 2>/dev/null || echo "  (chown may require elevated privileges)"
chown $USER script.sh 2>/dev/null || echo "  (chown may require elevated privileges)"

# Try to change to different user (will likely fail but generates events)
chown nobody:nogroup empty_file.txt 2>/dev/null || echo "  (chown to nobody failed as expected)"

# ===== SYMLINK TESTS =====
log_test "6. Testing symlink creation"

# Regular symlinks
ln -s regular_file.txt symlink_to_file
ln -s subdir/ symlink_to_dir
ln -s /etc/passwd symlink_to_system_file
ln -s non_existent_target broken_symlink

# Relative and absolute symlinks
ln -s ../$(basename "$TEST_DIR")/regular_file.txt relative_symlink
ln -s "$TEST_DIR/script.sh" absolute_symlink

# Chain of symlinks
ln -s symlink_to_file symlink_chain_1
ln -s symlink_chain_1 symlink_chain_2

# ===== RENAME/MOVE TESTS =====
log_test "7. Testing file renames and moves"

# Simple rename
cp regular_file.txt file_to_rename.txt
mv file_to_rename.txt renamed_file.txt

# Move to subdirectory
mkdir -p move_test/
cp script.sh move_test/
mv binary_file.bin move_test/

# Rename with different extensions
cp touched_file.log data.log
mv data.log data.backup

# Cross-directory moves
mv move_test/script.sh ./moved_back_script.sh

# Atomic rename (common in editors and atomic file updates)
echo "new version" >temp_atomic_file.tmp
mv temp_atomic_file.tmp atomic_file.txt

# ===== FILE DELETION TESTS =====
log_test "8. Testing file deletion"

# Direct deletion
rm empty_file.txt
rm restricted_file.txt

# Deletion of symlinks
rm symlink_to_file
rm broken_symlink

# Directory removal
rm -rf move_test/

# Unlink system call (rm uses this)
echo "will be deleted" >delete_me.txt
rm delete_me.txt

# ===== TIMESTAMP MANIPULATION TESTS =====
log_test "9. Testing timestamp modifications"

# Touch to update timestamps
touch regular_file.txt
touch -t 202301010000 touched_file.log

# Set specific timestamps
touch -d "2023-06-15 10:30:00" renamed_file.txt

# Update access and modification times separately
touch -a script.sh       # access time only
touch -m random_file.bin # modification time only

# ===== COMPLEX SCENARIOS =====
log_test "10. Testing complex file operations"

# Simulate text editor behavior
echo "original content" >editor_test.txt
echo "editing..." >.editor_test.txt.tmp
mv .editor_test.txt.tmp editor_test.txt

# Simulate backup operations
cp editor_test.txt "$BACKUP_DIR/editor_test.backup"
gzip <editor_test.txt >"$BACKUP_DIR/editor_test.txt.gz"

# Simulate log rotation
for i in {1..3}; do
  echo "log entry $i $(date)" >>app.log
  sleep 0.5
done
mv app.log app.log.1
gzip app.log.1
touch app.log

# Simulate package installation pattern
mkdir -p package_test/{bin,lib,etc}
echo "#!/bin/bash" >package_test/bin/myapp
echo "config=value" >package_test/etc/myapp.conf
echo "library code" >package_test/lib/libmyapp.so
chmod 755 package_test/bin/myapp
chmod 644 package_test/etc/myapp.conf
chmod 755 package_test/lib/libmyapp.so

# Create some rapid-fire operations
log_test "11. Testing rapid file operations"
for i in {1..10}; do
  echo "rapid test $i" >"rapid_$i.txt"
  chmod 644 "rapid_$i.txt"
  mv "rapid_$i.txt" "rapid_renamed_$i.txt"
  rm "rapid_renamed_$i.txt"
done

# ===== SPECIAL FILE TYPES =====
log_test "12. Testing special file operations"

# FIFO (named pipe)
mkfifo test_pipe || echo "  (mkfifo may not be available)"

# Device files (if we have permission)
# mknod test_device c 1 3 2>/dev/null || echo "  (mknod requires elevated privileges)"

# Hard links
echo "hardlink test" >hardlink_original.txt
ln hardlink_original.txt hardlink_copy.txt
rm hardlink_original.txt # Should still leave hardlink_copy.txt

# Test with different file sizes
dd if=/dev/zero of=large_file.dat bs=1M count=1 2>/dev/null
dd if=/dev/zero of=small_file.dat bs=1 count=1 2>/dev/null

echo ""
echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}FIM Test Completed!${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""
echo "Check your FIM logs for the following event types:"
echo "• FILE_CREATE: New files created"
echo "• FILE_MODIFY: File content changes"
echo "• FILE_DELETE: File removals"
echo "• FILE_RENAME: File moves and renames"
echo "• CHMOD: Permission changes"
echo "• CHOWN: Ownership changes"
echo "• SYMLINK: Symbolic link creation"
echo "• TIMESTAMP: Timestamp modifications"
echo ""
echo "Test files created in: $TEST_DIR"
echo "Backup files created in: $BACKUP_DIR"
echo ""
echo -e "${BLUE}To run this test again:${NC}"
echo "  bash $0"
echo ""
echo -e "${YELLOW}Note: Some operations (like chown) may require elevated privileges${NC}"
echo -e "${YELLOW}but should still generate FIM events even when they fail.${NC}"
