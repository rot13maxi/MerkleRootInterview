#!/usr/bin/env python3

# Had an idea for an interview question. Wanted to see what it would look like/how long it would take.
# Step 1: Given a collection of strings, output a merkle root that commit to that collection
# Step 2: Given a string and a merkle tree, spit out a merkle inclusion proof if that string is in the merkle tree
# Step 3: Given a string, merkle inclusion proof, and merkle root, validate that the root does in-fact commit the string

import hashlib
import math


def h(item):
    '''
    :param item: the thing to be hashed
    :return: hex-encoded hash of the item
    '''
    m = hashlib.sha256()
    m.update(item)
    return m.hexdigest()


class Node:
    def hash(self):
        raise NotImplemented


class LeafNode(Node):
    def __init__(self, contents):
        self.contents = contents

    def hash(self):
        if self.contents is None:
            return h(b"empty")
        return h(self.contents)


class ParentNode(Node):
    def __init__(self, left, right):
        self.left = left
        self.right = right

    def hash(self):
        s = sorted([self.left.hash(), self.right.hash()])
        return h(("%s:%s" % (s[0], s[1])).encode("utf-8"))


def make_merkle_tree(items):
    if len(items) == 0:
        return LeafNode(None).hash()
    next_level = []
    curr_level = [LeafNode(i) for i in items]
    # Pad the set with empty items so we have a full tree
    if not math.log2(len(curr_level)).is_integer():
        c = math.ceil(math.log2(len(curr_level)))
        upper = 2 ** c
        num_to_add = upper - len(curr_level)
        for i in range(num_to_add):
            curr_level.append(LeafNode(None))
    while True:
        if len(curr_level) == 1 and next_level == []:
            return curr_level[0]
        l = curr_level.pop()
        r = curr_level.pop()
        next_level.append(ParentNode(l, r))
        if len(curr_level) == 0:
            curr_level = next_level
            next_level = []


def make_merkle_proof(item, root_node):
    item_hash = h(item)
    if isinstance(root_node.left, LeafNode):
        if item_hash == root_node.left.hash():
            return [root_node.right.hash()]
        elif item_hash == root_node.right.hash():
            return [root_node.left.hash()]
        else:
            return None
    else:
        lh = make_merkle_proof(item, root_node.left)
        rh = make_merkle_proof(item, root_node.right)
        if lh is None and rh is None:
            return None
        else:
            return [lh or root_node.left.hash(), rh or root_node.right.hash()]


def validate_proof(item, root_hash, proof):
    if proof is None:
        return False

    def hash_item(i):
        if isinstance(i, str):
            return i
        elif isinstance(i, list):
            if len(i) == 1:
                left = i[0]
                right = h(item)
            else:
                left = hash_item(i[0])
                right = hash_item(i[1])
            s = sorted([left, right])
            return h(("%s:%s" % (s[0], s[1])).encode("utf-8"))

    return root_hash == hash_item(proof)


def main():
    sample = """
        Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed auctor facilisis orci. Etiam at quam finibus, accumsan lacus sit amet, tempus dolor. Sed aliquam tempor scelerisque. Phasellus sollicitudin dignissim lorem eget sollicitudin. Pellentesque viverra nisi ut magna blandit vestibulum. Morbi eget semper sem. Maecenas ut ligula mauris. Cras at rutrum turpis, et pellentesque neque. Maecenas at dui urna. Maecenas vel nulla dolor. Fusce at laoreet risus.
        Aenean condimentum urna non tortor accumsan, vel pulvinar libero feugiat. Cras sit amet ex posuere, condimentum ex sit amet, dignissim quam. Lorem ipsum dolor sit amet, consectetur adipiscing elit. Praesent interdum sem in malesuada sollicitudin. Curabitur quis ligula lacus. Donec pellentesque vitae erat eget vestibulum. Ut et diam quam. Pellentesque faucibus volutpat ex. Mauris gravida tincidunt felis sit amet congue. Cras nibh velit, porttitor eget semper nec, porttitor vitae ex. In augue augue, rutrum a porta quis, venenatis non mi. Etiam ullamcorper posuere enim sagittis cursus.
        Ut vitae purus consectetur, commodo libero in, sagittis augue. Curabitur gravida lectus eget bibendum tincidunt. Vivamus accumsan elit non turpis varius, eget lacinia metus semper. In convallis iaculis commodo. Proin euismod diam eu pretium elementum. Maecenas odio elit, efficitur sed sagittis eu, elementum fermentum erat. Suspendisse gravida dignissim ipsum, sed faucibus neque. Vivamus tempor lacinia risus, pellentesque pulvinar nisi eleifend id. Pellentesque vel placerat sapien. Nullam mi turpis, hendrerit tristique ornare a, congue vel lectus. Etiam semper eu sapien sit amet vestibulum.
        Nulla elementum nisl augue, imperdiet rhoncus libero facilisis vel. Sed facilisis in sapien sed imperdiet. Suspendisse fringilla est porttitor est venenatis semper. Cras enim nulla, vestibulum ut eleifend eget, suscipit at nisi. Praesent et vestibulum orci, et vehicula urna. Nullam id justo odio. Nullam eu diam justo. In hac habitasse platea dictumst. Ut in neque eu arcu convallis ultrices nec eu nulla. Aenean sit amet odio vitae diam luctus malesuada ut sit amet tellus. Morbi posuere sollicitudin leo, quis tincidunt libero commodo ut. Quisque et arcu orci. Morbi sed erat sem. Suspendisse fringilla nulla vel bibendum hendrerit. Curabitur vehicula est sit amet turpis accumsan sodales. Vestibulum tortor lectus, finibus nec auctor nec, sodales id eros.
        Aenean non metus pellentesque, rutrum quam sed, pretium ex. In eget maximus ipsum. Praesent condimentum sagittis erat, vel tincidunt sem auctor id. Morbi at venenatis felis. Mauris luctus neque at tellus laoreet dignissim. Curabitur dignissim, nisl quis eleifend ultricies, lacus ante pellentesque leo, quis dapibus nulla ante at sapien. Cras in ex orci. Etiam sed volutpat ligula. Pellentesque viverra augue enim, sit amet finibus dui tempor non. Donec quis erat sed mauris blandit dictum vitae non nulla.
    """
    items = [x.encode("utf-8") for x in sample.split()]
    tree = make_merkle_tree(items)

    print("Here is a sample of text:")
    print(sample)
    print("*************")
    print("Here is a merkle root that commits to the sample: ", tree.hash())
    print("type a word. If it's in the sample, I'll give you a merkle inclusion proof.")
    item = input("Word you want: ").encode("utf-8")
    proof = make_merkle_proof(item, tree)
    print("Here's your merkle proof:")
    print(proof)
    print("*************")
    print("Item is commited to by the merkle root: ", validate_proof(item, tree.hash(), proof))


if __name__ == '__main__':
    main()
