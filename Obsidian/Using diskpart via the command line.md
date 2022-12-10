Here is a quick guide is using diskpart.exe to extend or shrink a partition. Open your command prompt and type diskpart.exe, then hit enter. Allow the prompt at the UAC if it shows. The current disk/partition setup has a single disk with 3x partitions. [![image](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/09/image_thumb.png "image")]
(http://www.cogenesis.com.au/blog/wp-content/uploads/2014/09/image.png) 
I want to select disk 0, list the volumes and select the volume with C: on it: select disk 0 list volume 

select volume 2 [![image](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/09/image_thumb1.png "image")](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/09/image1.png) 
Let's shrink volume 2 (C:) by 20000MB (Almost 20GB): shrink desired=20000 [![image](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/09/image_thumb2.png "image")](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/09/image2.png) 
We now have the following setup: [![image](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/09/image_thumb3.png "image")](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/09/image3.png) 
We can now just re-extend this: extend [![image](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/09/image_thumb4.png "image")](http://www.cogenesis.com.au/blog/wp-content/uploads/2014/09/image4.png) 
As we had volume 2 selected, typing just 'extend' this will reclaim all unallocated space.