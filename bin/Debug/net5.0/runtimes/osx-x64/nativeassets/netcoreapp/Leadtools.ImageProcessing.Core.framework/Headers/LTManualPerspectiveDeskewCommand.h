//
//  LTManualPerspectiveDeskewCommand.h
//  Leadtools.ImageProcessing.Core
//
//  Copyright (c) 1991-2020 LEAD Technologies, Inc. All rights reserved.
//

#import <Leadtools/LTRasterCommand.h>
#import <Leadtools/LTRasterImage.h>
#import <Leadtools/LTPrimitives.h>

NS_ASSUME_NONNULL_BEGIN

NS_CLASS_AVAILABLE(10_10, 8_0)
@interface LTManualPerspectiveDeskewCommand : LTRasterCommand

@property (nonatomic, strong, nullable)           NSArray<NSValue *> *inputPoints; //LeadPoint
@property (nonatomic, strong, nullable)           NSArray<NSValue *> *mappingPoints; //LeadPoint

@property (nonatomic, strong, readonly, nullable) LTRasterImage *outputImage;

- (instancetype)initWithInPoints:(nullable NSArray<NSValue *> *)inputPoints mappingPoints:(nullable NSArray<NSValue *> *)mappingPoints NS_DESIGNATED_INITIALIZER;

@end

NS_ASSUME_NONNULL_END
