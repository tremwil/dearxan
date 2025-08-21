//! Intrusive index-based linked list.

use std::{
    marker::PhantomData,
    ops::{Deref, DerefMut, Index, IndexMut},
    ptr::NonNull,
};

use nonmax::NonMaxUsize;

#[repr(transparent)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct IListIndex(NonMaxUsize);

impl IListIndex {
    pub fn index(&self) -> usize {
        self.0.get()
    }
}

impl From<IListIndex> for usize {
    fn from(value: IListIndex) -> Self {
        value.index()
    }
}

impl TryFrom<usize> for IListIndex {
    type Error = <NonMaxUsize as TryFrom<usize>>::Error;

    fn try_from(value: usize) -> Result<Self, Self::Error> {
        Ok(Self(value.try_into()?))
    }
}

#[cfg(target_pointer_width = "64")]
impl From<u32> for IListIndex {
    fn from(value: u32) -> Self {
        Self(NonMaxUsize::new(value as usize).unwrap())
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct IListLink {
    prev: Option<IListIndex>,
    next: Option<IListIndex>,
}

impl IListLink {
    fn clear(&mut self) {
        self.prev = None;
        self.next = None;
    }

    pub fn prev(&self) -> Option<IListIndex> {
        self.prev
    }

    pub fn next(&self) -> Option<IListIndex> {
        self.next
    }
}

#[derive(Default, Debug, Clone, Copy)]
pub struct IListEnds {
    head: Option<IListIndex>,
    tail: Option<IListIndex>,
}

impl IListEnds {
    pub fn head_index(&self) -> Option<IListIndex> {
        self.head
    }

    pub fn tail_index(&self) -> Option<IListIndex> {
        self.tail
    }

    pub fn head<'a, C>(&self, container: &'a C) -> Option<NodeRef<'a, C>>
    where
        C: Index<usize, Output: IListNode> + ?Sized,
    {
        Some(NodeRef::new(container, self.head?))
    }

    pub fn tail<'a, C>(&self, container: &'a C) -> Option<NodeRef<'a, C>>
    where
        C: Index<usize, Output: IListNode> + ?Sized,
    {
        Some(NodeRef::new(container, self.tail?))
    }

    pub fn head_mut<'a, C>(&self, container: &'a mut C) -> Option<NodeMut<'a, C>>
    where
        C: IndexMut<usize, Output: IListNode> + ?Sized,
    {
        Some(NodeMut::new(container, self.head?))
    }

    pub fn tail_mut<'a, C>(&self, container: &'a mut C) -> Option<NodeMut<'a, C>>
    where
        C: IndexMut<usize, Output: IListNode> + ?Sized,
    {
        Some(NodeMut::new(container, self.tail?))
    }

    pub fn push_head<'a, C>(&mut self, cursor: &mut NodeMut<'a, C>)
    where
        C: IndexMut<usize, Output: IListNode> + ?Sized,
    {
        cursor.link_mut().next = self.head;
        if let Some(i) = self.head {
            cursor.with_raw_parts(|container, index| {
                container.index_mut(i.index()).link_mut().prev = Some(index)
            });
        }
        else {
            self.tail = Some(cursor.index());
        }
        self.head = Some(cursor.index());
    }

    pub fn push_tail<'a, C>(&mut self, cursor: &mut NodeMut<'a, C>)
    where
        C: IndexMut<usize, Output: IListNode> + ?Sized,
    {
        cursor.link_mut().prev = self.tail;
        if let Some(i) = self.tail {
            cursor.with_raw_parts(|container, index| {
                container.index_mut(i.index()).link_mut().next = Some(index)
            });
        }
        else {
            self.head = Some(cursor.index());
        }
        self.tail = Some(cursor.index());
    }

    pub fn remove<'a, C>(&mut self, cursor: &mut NodeMut<'a, C>) -> IListLink
    where
        C: IndexMut<usize, Output: IListNode> + ?Sized,
    {
        cursor.excise(self)
    }

    pub fn iter<'a, C>(&self, container: &'a C) -> impl Iterator<Item = NodeRef<'a, C>>
    where
        C: Index<usize, Output: IListNode>,
    {
        let mut current = self.head.map(|h| NodeRef::new(container, h));
        std::iter::from_fn(move || {
            let c = current?;
            current = c.next();
            Some(c)
        })
    }

    pub fn iter_rev<'a, C>(&self, container: &'a C) -> impl Iterator<Item = NodeRef<'a, C>>
    where
        C: Index<usize, Output: IListNode>,
    {
        let mut current = self.tail.map(|h| NodeRef::new(container, h));
        std::iter::from_fn(move || {
            let c = current?;
            current = c.prev();
            Some(c)
        })
    }
}

pub trait IListNode {
    fn link(&self) -> &IListLink;
    fn link_mut(&mut self) -> &mut IListLink;
}

pub trait IndexNode: Index<usize, Output: IListNode> {
    fn node(&self, index: usize) -> NodeRef<'_, Self> {
        NodeRef::new(self, index.try_into().unwrap())
    }

    fn node_mut(&mut self, index: usize) -> NodeMut<'_, Self>
    where
        Self: IndexMut<usize>,
    {
        NodeMut::new(self, index.try_into().unwrap())
    }
}

impl<C: Index<usize, Output: IListNode> + ?Sized> IndexNode for C {}

#[derive(Debug)]
pub struct NodeRef<'a, C: Index<usize, Output: IListNode> + ?Sized> {
    container: &'a C,
    item: &'a C::Output,
}

impl<'a, C: Index<usize, Output: IListNode> + ?Sized> Clone for NodeRef<'a, C> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, C: Index<usize, Output: IListNode> + ?Sized> Copy for NodeRef<'a, C> {}

impl<'a, C: Index<usize, Output: IListNode> + ?Sized> NodeRef<'a, C> {
    pub fn new(container: &'a C, index: IListIndex) -> Self {
        Self {
            container,
            item: container.index(index.index()),
        }
    }

    pub fn prev_index(&self) -> Option<IListIndex> {
        self.item.link().prev
    }

    pub fn next_index(&self) -> Option<IListIndex> {
        self.item.link().next
    }

    pub fn prev(&self) -> Option<Self> {
        Some(NodeRef::new(self.container, self.prev_index()?))
    }

    pub fn next(&self) -> Option<Self> {
        Some(NodeRef::new(self.container, self.next_index()?))
    }

    pub fn container(&self) -> &C {
        &self.container
    }

    pub fn iter(&self) -> impl Iterator<Item = NodeRef<'a, C>> {
        let mut current = Some(*self);
        std::iter::from_fn(move || {
            let c = current?;
            current = c.next();
            Some(c)
        })
    }

    pub fn iter_rev(&self) -> impl Iterator<Item = NodeRef<'a, C>> {
        let mut current = Some(*self);
        std::iter::from_fn(move || {
            let c = current?;
            current = c.prev();
            Some(c)
        })
    }
}

impl<C: Index<usize, Output: IListNode> + ?Sized> Deref for NodeRef<'_, C> {
    type Target = C::Output;

    fn deref(&self) -> &Self::Target {
        self.item
    }
}

#[derive(Debug)]
pub struct NodeMut<'a, C: IndexMut<usize, Output: IListNode> + ?Sized> {
    container_ptr: NonNull<C>,
    item_ptr: NonNull<C::Output>,
    index: IListIndex,
    phantom: PhantomData<(&'a mut C, &'a mut C::Output)>,
}

impl<'a, T: IListNode + ?Sized, C: IndexMut<usize, Output = T> + ?Sized> NodeMut<'a, C> {
    pub fn new(container: &'a mut C, index: IListIndex) -> Self {
        Self {
            container_ptr: container.into(),
            item_ptr: container.index_mut(index.index()).into(),
            index,
            phantom: PhantomData,
        }
    }

    pub fn prev_index(&self) -> Option<IListIndex> {
        unsafe { self.item_ptr.as_ref() }.link().prev
    }

    pub fn next_index(&self) -> Option<IListIndex> {
        unsafe { self.item_ptr.as_ref() }.link().next
    }

    pub fn prev(&self) -> Option<NodeRef<'_, C>> {
        let container = unsafe { self.container_ptr.as_ref() };
        Some(NodeRef::new(container, self.prev_index()?))
    }

    pub fn next(&self) -> Option<NodeRef<'_, C>> {
        let container = unsafe { self.container_ptr.as_ref() };
        Some(NodeRef::new(container, self.next_index()?))
    }

    pub fn container(&self) -> &C {
        unsafe { self.container_ptr.as_ref() }
    }

    pub fn into_raw_parts(mut self) -> (&'a mut C, IListIndex) {
        (unsafe { self.container_ptr.as_mut() }, self.index)
    }

    pub fn with_raw_parts<F, R>(&mut self, fun: F) -> R
    where
        F: FnOnce(&mut C, IListIndex) -> R,
    {
        let container = unsafe { self.container_ptr.as_mut() };
        let ret = fun(container, self.index);
        self.item_ptr = container.index_mut(self.index.index()).into();
        ret
    }

    pub fn index(&self) -> IListIndex {
        self.index
    }

    pub fn with_prev<F, R>(&mut self, fun: F) -> Option<R>
    where
        F: for<'b> FnOnce(NodeMut<'b, C>) -> R,
    {
        let prev = self.prev_index()?;
        Some(self.with_raw_parts(|container, _| fun(NodeMut::new(container, prev))))
    }

    pub fn with_next<F, R>(&mut self, fun: F) -> Option<R>
    where
        F: for<'b> FnOnce(NodeMut<'b, C>) -> R,
    {
        let next = self.next_index()?;
        Some(self.with_raw_parts(|container, _| fun(NodeMut::new(container, next))))
    }

    pub fn into_prev(mut self) -> Option<Self> {
        let prv_index = self.prev_index()?;
        let container = unsafe { self.container_ptr.as_mut() };
        Some(NodeMut::new(container, prv_index))
    }

    pub fn into_next(mut self) -> Option<Self> {
        let next_index = self.next_index()?;
        let container = unsafe { self.container_ptr.as_mut() };
        Some(NodeMut::new(container, next_index))
    }

    pub fn into_item(mut self) -> &'a mut T {
        unsafe { self.item_ptr.as_mut() }
    }

    pub fn excise(&mut self, list: &mut IListEnds) -> IListLink {
        let link = *self.link();
        self.link_mut().clear();

        let container = unsafe { self.container_ptr.as_mut() };

        match link.next {
            Some(i) => container.index_mut(i.index()).link_mut().prev = link.prev,
            None => list.tail = link.prev,
        };
        match link.prev {
            Some(i) => container.index_mut(i.index()).link_mut().next = link.next,
            None => list.head = link.next,
        };
        // update ptr in case of reference invalidation
        self.item_ptr = container.index_mut(self.index.index()).into();
        link
    }

    pub fn excise_and_prev(mut self, list: &mut IListEnds) -> Option<Self> {
        let old_link = self.excise(list);
        let (container, _) = self.into_raw_parts();
        Some(Self::new(container, old_link.prev?))
    }

    pub fn excise_and_next(mut self, list: &mut IListEnds) -> Option<Self> {
        let old_link = self.excise(list);
        let (container, _) = self.into_raw_parts();
        Some(Self::new(container, old_link.next?))
    }

    pub fn insert_head(&mut self, list: &mut IListEnds) {
        list.push_head(self);
    }

    pub fn insert_tail(&mut self, list: &mut IListEnds) {
        list.push_tail(self);
    }
}

impl<'a, T: IListNode> NodeMut<'a, [T]> {
    pub fn as_container(&mut self) -> &mut [T] {
        unsafe { self.container_ptr.as_mut() }
    }

    pub fn prev_mut(&mut self) -> Option<NodeMut<'_, [T]>> {
        let prev_index = self.prev_index()?;
        let container = unsafe { self.container_ptr.as_mut() };
        Some(NodeMut::new(container, prev_index))
    }

    pub fn next_mut(&mut self) -> Option<NodeMut<'_, [T]>> {
        let next_index = self.next_index()?;
        let container = unsafe { self.container_ptr.as_mut() };
        Some(NodeMut::new(container, next_index))
    }
}

impl<'a, T: IListNode> NodeMut<'a, Vec<T>> {
    pub fn as_container_slice(&mut self) -> &mut [T] {
        unsafe { self.container_ptr.as_mut().as_mut_slice() }
    }

    pub fn prev_mut(&mut self) -> Option<NodeMut<'_, [T]>> {
        let prev_index = self.prev_index()?;
        let container = unsafe { self.container_ptr.as_mut() };
        Some(NodeMut::new(container, prev_index))
    }

    pub fn next_mut(&mut self) -> Option<NodeMut<'_, [T]>> {
        let next_index = self.next_index()?;
        let container = unsafe { self.container_ptr.as_mut() };
        Some(NodeMut::new(container, next_index))
    }
}

impl<'a, C: IndexMut<usize, Output: IListNode> + ?Sized + 'a> Deref for NodeMut<'a, C> {
    type Target = C::Output;

    fn deref(&self) -> &Self::Target {
        unsafe { self.item_ptr.as_ref() }
    }
}

impl<'a, C: IndexMut<usize, Output: IListNode> + ?Sized + 'a> DerefMut for NodeMut<'a, C> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { self.item_ptr.as_mut() }
    }
}

unsafe impl<C: IndexMut<usize, Output: IListNode + Send> + ?Sized + Send> Send for NodeMut<'_, C> {}
unsafe impl<C: IndexMut<usize, Output: IListNode + Sync> + ?Sized + Sync> Sync for NodeMut<'_, C> {}

#[cfg(test)]
mod tests {
    use crate::analysis::ssa::intrusive_ilist::{IListEnds, IListLink, IListNode, IndexNode};

    struct Node {
        link: IListLink,
        val: usize,
    }

    impl Node {
        fn new(val: usize) -> Self {
            Node {
                link: Default::default(),
                val,
            }
        }
    }

    impl IListNode for Node {
        fn link(&self) -> &IListLink {
            &self.link
        }

        fn link_mut(&mut self) -> &mut IListLink {
            &mut self.link
        }
    }

    #[test]
    fn test_ilist_insert() {
        let mut list = IListEnds::default();
        let mut nodes = vec![Node::new(1), Node::new(2), Node::new(3)];
        nodes.node_mut(1).insert_tail(&mut list);

        assert_eq!(list.head, Some(1usize.try_into().unwrap()));
        assert_eq!(list.tail, Some(1usize.try_into().unwrap()));

        nodes.node_mut(2).insert_tail(&mut list);
        nodes.node_mut(0).insert_head(&mut list);

        assert_eq!(list.head, Some(0usize.try_into().unwrap()));
        assert_eq!(list.tail, Some(2usize.try_into().unwrap()));

        let vals: Vec<_> = list.iter(&nodes).map(|n| n.val).collect();
        assert_eq!(vals, &[1, 2, 3]);

        let vals_rev: Vec<_> = list.iter_rev(&nodes).map(|n| n.val).collect();
        assert_eq!(vals_rev, &[3, 2, 1])
    }

    #[test]
    fn test_ilist_remove() {
        let mut list = IListEnds::default();
        let mut nodes: Vec<_> = (0..25).map(Node::new).collect();

        for i in 0..nodes.len() {
            nodes.node_mut(i).insert_tail(&mut list);
        }

        // remove all multiples of 3
        let mut current = list.head_mut(&mut nodes);
        while let Some(c) = current {
            if c.val.is_multiple_of(3) {
                current = c.excise_and_next(&mut list);
            }
            else {
                current = c.into_next()
            }
        }

        let expected: Vec<_> = (0..25usize).filter(|&n| !n.is_multiple_of(3)).collect();
        let actual: Vec<_> = list.iter(&nodes).map(|n| n.val).collect();
        assert_eq!(expected, actual)
    }
}
