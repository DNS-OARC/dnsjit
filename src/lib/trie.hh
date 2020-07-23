/*
 * Copyright (C) 2017-2019 CZ.NIC, z.s.p.o. <knot-dns@labs.nic.cz>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/* Memory allocation function prototypes. */
typedef void* (*knot_mm_alloc_t)(void* ctx, size_t len);
typedef void (*knot_mm_free_t)(void* p);

/*! \brief Memory allocation context. */
typedef struct knot_mm {
    void*           ctx; /* \note Must be first */
    knot_mm_alloc_t alloc;
    knot_mm_free_t  free;
} knot_mm_t;

/*!
 * \brief Native API of QP-tries:
 *
 * - keys are uint8_t strings, not necessarily zero-terminated,
 *   the structure copies the contents of the passed keys
 * - values are void* pointers, typically you get an ephemeral pointer to it
 * - key lengths are limited by 2^32-1 ATM
 */

/*! \brief Element value. */
typedef void* trie_val_t;

/*! \brief Opaque structure holding a QP-trie. */
typedef struct trie trie_t;

/*! \brief Opaque type for holding a QP-trie iterator. */
typedef struct trie_it trie_it_t;

/*! \brief Create a trie instance.  Pass NULL to use malloc+free. */
trie_t* trie_create(knot_mm_t* mm);

/*! \brief Free a trie instance. */
void trie_free(trie_t* tbl);

/*! \brief Clear a trie instance (make it empty). */
void trie_clear(trie_t* tbl);

/*! \brief Return the number of keys in the trie. */
size_t trie_weight(const trie_t* tbl);

/*! \brief Search the trie, returning NULL on failure. */
trie_val_t* trie_get_try(trie_t* tbl, const uint8_t* key, uint32_t len);

/*!
 * \brief Return pointer to the minimum.  Optionally with key and its length. */
trie_val_t* trie_get_first(trie_t* tbl, uint8_t** key, uint32_t* len);

/*! \brief Search the trie, inserting NULL trie_val_t on failure. */
trie_val_t* trie_get_ins(trie_t* tbl, const uint8_t* key, uint32_t len);

/*!
 * \brief Search for less-or-equal element.
 *
 * \param tbl  Trie.
 * \param key  Searched key.
 * \param len  Key length.
 * \param val  Must be valid; it will be set to NULL if not found or errored.
 * \return KNOT_EOK for exact match, 1 for previous, KNOT_ENOENT for not-found,
 *         or KNOT_E*.
 */
int trie_get_leq(trie_t* tbl, const uint8_t* key, uint32_t len, trie_val_t** val);

/*!
 * \brief Apply a function to every trie_val_t, in order.
 *
 * \param d Parameter passed as the second argument to f().
 * \return First nonzero from f() or zero (i.e. KNOT_EOK).
 */
int trie_apply(trie_t* tbl, int (*f)(trie_val_t*, void*), void* d);

/*! \brief Create a new iterator pointing to the first element (if any). */
trie_it_t* trie_it_begin(trie_t* tbl);

/*!
 * \brief Advance the iterator to the next element.
 *
 * Iteration is in ascending lexicographical order.
 * In particular, the empty string would be considered as the very first.
 *
 * \note You may not use this function if the trie's key-set has been modified
 * during the lifetime of the iterator (modifying values only is OK).
 */
void trie_it_next(trie_it_t* it);

/*! \brief Test if the iterator has gone past the last element. */
bool trie_it_finished(trie_it_t* it);

/*! \brief Free any resources of the iterator. It's OK to call it on NULL. */
void trie_it_free(trie_it_t* it);

/*!
 * \brief Return pointer to the key of the current element.
 *
 * \note The optional len is uint32_t internally but size_t is better for our usage,
 *       as it is without an additional type conversion.
 */
const uint8_t* trie_it_key(trie_it_t* it, size_t* len);

/*! \brief Return pointer to the value of the current element (writable). */
trie_val_t* trie_it_val(trie_it_t* it);
