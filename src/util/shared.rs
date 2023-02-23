use std::sync::{Arc, Mutex, Weak};

#[derive(Clone, Debug, )]
pub enum Shared<O: ?Sized> {
    Owned(Arc<Mutex<O>>),
    Borrowed(Weak<Mutex<O>>)
}

#[macro_export]
macro_rules! default_shared {
    ($T:ty) => {
        impl Default for Shared<$T> {
            fn default() -> Self {
                use std::sync::{Mutex, Weak};
                Shared::Borrowed(Weak::<Mutex<$T>>::new())
            }
        }
    };
}
// impl<O: ?Sized> Default for Shared<O> {
//     fn default() -> Self {
//         Shared::Borrowed(Weak::<Mutex<O>>::new())
//     }
// }

impl<O: ?Sized> Shared<O> {

    // pub fn unlock(&self) {
    //     match *self {
    //         Self::Owned(mutex) => {
    //             mutex.
    //         },
    //         Self::Borrowed(ref weak) => {}
    //     }
    // }
    pub fn with<F, T>(&self, f: F) -> T where F: FnOnce(&mut O) -> T {
        match *self {
            Self::Owned(ref mutex) => {
                match mutex.lock() {
                    Ok(mut guard) => f(&mut *guard),
                    Err(err) => {
                        println!("The counter was poisoned: {:?}", err);
                        unimplemented!()
                    }
                }
            }
            Self::Borrowed(ref weak) => {
                let mutex = weak.upgrade()
                    .expect("Shared::Borrowed no longer valid");
                let x = match mutex.lock() {
                    Ok(mut guard) => f(&mut *guard),
                    Err(err) => {
                        println!("The counter was poisoned: {:?}", err);
                        unimplemented!()
                    }
                }; x
            }
        }
    }
    pub fn borrow(&self) -> Shared<O> {
        match *self {
            Self::Owned(ref arc) => Self::Borrowed(Arc::downgrade(arc)),
            Self::Borrowed(ref weak) => Self::Borrowed(weak.clone())
        }
    }
}

pub trait Shareable {
    fn to_shared(self) -> Shared<Self> where Self: Sized {
        Shared::Owned(Arc::new(Mutex::new(self)))
    }
    fn to_weak(self) -> Shared<Self> where Self: Sized {
        Shared::Borrowed(Weak::<Mutex<Self>>::new())
    }
}


/*use proc_macro::TokenStream;
use quote::quote;
use syn::{DeriveInput, Result};

#[proc_macro_derive(Shareable, attributes(shareable))]
pub fn shareable_derive(input: TokenStream) -> TokenStream {
    let input = syn::parse_macro_input!(input as DeriveInput);
    let name = input.ident;

    let result = impl_shareable(name);
    result.unwrap_or_else(|e| e.to_compile_error()).into()
}

fn impl_shareable(name: syn::Ident) -> Result<TokenStream> {
    let to_shared = quote! {
        fn to_shared(self) -> Shared<Self> where Self: Sized {
            Shared::Owned(Arc::new(Mutex::new(self)))
        }
    };
    let to_weak = quote! {
        fn to_weak(self) -> Shared<Self> where Self: Sized {
            Shared::Borrowed(Weak::<Mutex<Self>>::new())
        }
    };

    let result = quote! {
        impl Shareable for #name {
            #to_shared
            #to_weak
        }
    };

    Ok(result)
}
*/
