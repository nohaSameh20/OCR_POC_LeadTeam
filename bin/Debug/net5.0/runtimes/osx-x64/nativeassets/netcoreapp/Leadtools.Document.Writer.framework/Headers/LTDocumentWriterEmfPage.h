//
//  LTDocumentWriterEmfPage.h
//  Leadtools.Document.Writer
//
//  Copyright (c) 1991-2020 LEAD Technologies, Inc. All rights reserved.
//

#import <Leadtools/LTRasterImage.h>
#import <Leadtools.Document.Writer/LTDocumentWriterPage.h>

NS_CLASS_AVAILABLE(10_10, 8_0)
@interface LTDocumentWriterEmfPage : LTDocumentWriterPage <NSCopying>

@property (nonatomic, assign) void *emfHandle;
@property (nonatomic, strong) LTRasterImage *image;

@end
