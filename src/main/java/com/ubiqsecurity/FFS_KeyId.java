package com.ubiqsecurity;


class FFS_KeyId {
  Integer key_number;
  FFS_Record ffs;

  FFS_KeyId(FFS_Record ffs, Integer number) {
    this.ffs = ffs;
    this.key_number = number; // May be NULL - indicating an encrypt using currently active key
  }

  @Override
  public int hashCode() {
    int result = 17;
    result = 31 * result + ((ffs != null && ffs.getName() != null) ? ffs.getName().hashCode() : 0);
    result = 31 * result + ((key_number != null) ? key_number.hashCode() : 0);
    return result;
  }

  @Override
  public boolean equals(Object obj) {
    if (this == obj) return true;
    if (obj == null) return false;
    if (getClass() != obj.getClass()) return false;
    final FFS_KeyId other = (FFS_KeyId) obj;

    // If FFS in both are NULL, return FALSE
    if (((this.ffs == null) == (other.ffs == null)) && (this.ffs == null)) return false;

    // Use string value equals not object reference equals.
    if (!this.ffs.getName().equals(other.ffs.getName())) {
        return false;
    }
    // If one key number is NULL and the other isn't, return false
    if ((this.key_number == null) != (other.key_number == null)) return false;
    // If both keys are NULL, return true
    if (((this.key_number == null) == (other.key_number == null)) && (this.key_number == null)) return true;
    // Compare value of the key number
    return (this.key_number.equals(other.key_number));
  }

}